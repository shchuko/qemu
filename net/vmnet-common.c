/*
 * vmnet.c - network client wrapper for Apple vmnet.framework
 *
 * Copyright(c) 2021 Vladislav Yaroshchuk <yaroshchuk2000@gmail.com>
 * Copyright(c) 2021 Phillip Tennen <phillip@axleos.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "qapi-types-net.h"
#include "vmnet_int.h"
#include "clients.h"
#include "qemu/error-report.h"
#include "qapi/error.h"

#include <vmnet/vmnet.h>
#include <dispatch/dispatch.h>

static void vmnet_read_poll(NetClientState *nc, bool enable);

static void vmnet_write_poll(NetClientState *nc, bool enable);

static bool vmnet_can_read(NetClientState *nc);

static bool vmnet_can_write(NetClientState *nc);

static void vmnet_bufs_init(VmnetCommonState *s);

static struct vmpktdesc *iov_to_packets(const struct iovec *iov, int iovcnt,
                                        uint64_t max_packet_size, int *pkt_cnt);

static void vmnet_read_handler(NetClientState *nc,
                               interface_event_t event_id,
                               xpc_object_t event);

static void vmnet_send_completed(NetClientState *nc, ssize_t len);


const char *vmnet_status_map_str(vmnet_return_t status)
{
    switch (status) {
    case VMNET_SUCCESS:
        return "success";
    case VMNET_FAILURE:
        return "general failure";
    case VMNET_MEM_FAILURE:
        return "memory allocation failure";
    case VMNET_INVALID_ARGUMENT:
        return "invalid argument specified";
    case VMNET_SETUP_INCOMPLETE:
        return "interface setup is not complete";
    case VMNET_INVALID_ACCESS:
        return "invalid access, permission denied";
    case VMNET_PACKET_TOO_BIG:
        return "packet size is larger than MTU";
    case VMNET_BUFFER_EXHAUSTED:
        return "buffers exhausted in kernel";
    case VMNET_TOO_MANY_PACKETS:
        return "packet count exceeds limit";
    default:
        return "unknown vmnet error";
    }
}


int vmnet_if_create(NetClientState *nc,
                    xpc_object_t if_desc,
                    Error **errp,
                    void (*completion_callback)(xpc_object_t interface_param))
{
    VmnetCommonState *s;

    dispatch_queue_t if_create_q;
    dispatch_semaphore_t if_created_sem;

    __block vmnet_return_t if_status;

    if_create_q = dispatch_queue_create("org.qemu.vmnet.create",
                                        DISPATCH_QUEUE_SERIAL);
    if_created_sem = dispatch_semaphore_create(0);

    s = DO_UPCAST(VmnetCommonState, nc, nc);
    s->vmnet_if = vmnet_start_interface(
        if_desc,
        if_create_q,
        ^ (vmnet_return_t status, xpc_object_t interface_param) {
          if_status = status;
          if (status != VMNET_SUCCESS || !interface_param) {
                dispatch_semaphore_signal(if_created_sem);
                return;
          }

          s->mtu = xpc_dictionary_get_uint64(
              interface_param,
              vmnet_mtu_key);
          s->max_packet_size = xpc_dictionary_get_uint64(
              interface_param,
              vmnet_max_packet_size_key);

          if (completion_callback) {
                completion_callback(interface_param);
          }
          dispatch_semaphore_signal(if_created_sem);
        });

    if (s->vmnet_if == NULL) {
        error_setg(errp, "unable to create interface with requested params");
        return -1;
    }

    dispatch_semaphore_wait(if_created_sem, DISPATCH_TIME_FOREVER);
    dispatch_release(if_create_q);

    if (if_status != VMNET_SUCCESS) {
        error_setg(errp,
                   "interface creation error: %s",
                   vmnet_status_map_str(if_status));
        return -1;
    }

    s->avail_pkt_q = dispatch_queue_create(
        "org.qemu.vmnet.if_queue",
        DISPATCH_QUEUE_SERIAL
    );

    vmnet_bufs_init(s);

    vmnet_read_poll(nc, true);
    vmnet_write_poll(nc, true);

    return 0;
}

bool vmnet_can_receive_common(NetClientState *nc)
{
    return vmnet_can_write(nc);
}

ssize_t vmnet_receive_iov_common(NetClientState *nc,
                                 const struct iovec *iov,
                                 int iovcnt)
{
    VmnetCommonState *s;

    struct vmpktdesc *packets;
    int pkt_cnt;
    int pkt_cnt_written;

    size_t bytes_written;
    int i;

    vmnet_return_t if_status;

    s = DO_UPCAST(VmnetCommonState, nc, nc);

    packets = iov_to_packets(iov, iovcnt, s->max_packet_size, &pkt_cnt);
    if (pkt_cnt == -1) {
        return 0;
    }

    pkt_cnt_written = pkt_cnt;
    if_status = vmnet_write(s->vmnet_if, packets, &pkt_cnt_written);

    if (if_status != VMNET_SUCCESS) {
        error_printf("vmnet: write error: %s\n",
                     vmnet_status_map_str(if_status));
        return 0;
    }

    if (pkt_cnt_written != pkt_cnt) {
        error_printf("vmnet: %d packets dropped on write\n",
                     pkt_cnt - pkt_cnt_written);
    }

    bytes_written = 0;
    for (i = 0; i < pkt_cnt_written; ++i) {
        bytes_written += packets[i].vm_pkt_size;
    }

    for (i = 0; i < pkt_cnt; ++i) {
        g_free(packets[i].vm_pkt_iov);
    }
    g_free(packets);

    return bytes_written;
}

static void vmnet_bufs_init(VmnetCommonState *s)
{
    int i;
    struct vmpktdesc *packets;
    struct iovec *iov;

    s->iov_buf = g_new0(
    struct iovec, VMNET_PACKETS_LIMIT);
    s->packets_buf = g_new0(
    struct vmpktdesc, VMNET_PACKETS_LIMIT);

    packets = s->packets_buf;
    iov = s->iov_buf;

    for (i = 0; i < VMNET_PACKETS_LIMIT; ++i) {
        iov[i].iov_len = s->max_packet_size;
        iov[i].iov_base = g_malloc0(iov[i].iov_len);

        packets[i].vm_pkt_iov = iov + i;
        packets[i].vm_pkt_size = s->max_packet_size;
        packets[i].vm_flags = 0;
        packets[i].vm_pkt_iovcnt = 1;
    }
}

static struct vmpktdesc *iov_to_packets(const struct iovec *iov, int iovcnt,
                                        uint64_t max_packet_size, int *pkt_cnt)
{
    int iov_no;
    struct vmpktdesc *packets;
    size_t total_size;

    total_size = 0;
    for (iov_no = 0; iov_no < iovcnt; ++iov_no) {
        total_size += iov[iov_no].iov_len;
    }

    /* Collect all the iovecs into one packet */
    *pkt_cnt = 1;
    packets = g_new0(
    struct vmpktdesc, *pkt_cnt);

    packets[0].vm_pkt_iovcnt = iovcnt;
    packets[0].vm_flags = 0;
    packets[0].vm_pkt_size = total_size;
    packets[0].vm_pkt_iov = g_new0(
    struct iovec, iovcnt);
    memcpy(packets[0].vm_pkt_iov, iov, iovcnt * sizeof(struct iovec));

    return packets;
}

static void vmnet_read_handler(NetClientState *nc,
                               interface_event_t event_id,
                               xpc_object_t event)
{
    assert(event_id == VMNET_INTERFACE_PACKETS_AVAILABLE);
    assert(vmnet_can_read(nc));

    VmnetCommonState *s;
    uint64_t packets_available;

    struct iovec *iov;
    struct vmpktdesc *packets;
    int pkt_cnt;
    int i;

    vmnet_return_t if_status;
    ssize_t size;

    s = DO_UPCAST(VmnetCommonState, nc, nc);

    packets_available = xpc_dictionary_get_uint64(
        event,
        vmnet_estimated_packets_available_key
    );

    pkt_cnt = (packets_available < VMNET_PACKETS_LIMIT) ?
              packets_available :
              VMNET_PACKETS_LIMIT;


    iov = s->iov_buf;
    packets = s->packets_buf;

    for (i = 0; i < pkt_cnt; ++i) {
        packets[i].vm_pkt_size = s->max_packet_size;
        packets[i].vm_pkt_iovcnt = 1;
        packets[i].vm_flags = 0;
    }

    if_status = vmnet_read(s->vmnet_if, packets, &pkt_cnt);
    if (if_status != VMNET_SUCCESS) {
        error_printf("vmnet: read failed: %s\n",
                     vmnet_status_map_str(if_status));
    }

    for (i = 0; i < pkt_cnt; ++i) {
        size = qemu_send_packet_async(nc,
                                      iov[i].iov_base,
                                      packets[i].vm_pkt_size,
                                      vmnet_send_completed);
        if (size == 0) {
            vmnet_read_poll(nc, false);
        } else if (size < 0) {
            break;
        }
    }

}


static void vmnet_read_poll(NetClientState *nc, bool enable)
{
    VmnetCommonState *s;

    s = DO_UPCAST(VmnetCommonState, nc, nc);

    if (s->read_poll == enable) {
        return;
    }

    s->read_poll = enable;

    if (enable) {
        vmnet_interface_set_event_callback(
            s->vmnet_if,
            VMNET_INTERFACE_PACKETS_AVAILABLE,
            s->avail_pkt_q,
            ^ (interface_event_t event_id, xpc_object_t event) {
              qemu_mutex_lock_iothread();
              vmnet_read_handler(nc, event_id, event);
              qemu_mutex_unlock_iothread();
            });
    } else {
        vmnet_interface_set_event_callback(
            s->vmnet_if,
            VMNET_INTERFACE_PACKETS_AVAILABLE,
            NULL,
            NULL);
    }
}

static void vmnet_write_poll(NetClientState *nc, bool enable)
{
    VmnetCommonState *s = DO_UPCAST(VmnetCommonState, nc, nc);
    s->write_poll = enable;
}

static bool vmnet_can_read(NetClientState *nc)
{
    VmnetCommonState *s = DO_UPCAST(VmnetCommonState, nc, nc);
    return s->read_poll;
}

static bool vmnet_can_write(NetClientState *nc)
{
    VmnetCommonState *s = DO_UPCAST(VmnetCommonState, nc, nc);
    return s->write_poll;
}

static void vmnet_send_completed(NetClientState *nc, ssize_t len)
{
    vmnet_read_poll(nc, true);
}
