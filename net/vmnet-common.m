/*
 * vmnet-common.m - network client wrapper for Apple vmnet.framework
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

typedef struct vmpktdesc vmpktdesc_t;
typedef struct iovec iovec_t;

static void vmnet_read_poll(NetClientState *nc, bool enable);

static void vmnet_write_poll(NetClientState *nc, bool enable);

static void vmnet_bufs_init(VmnetCommonState *s);

static void vmnet_create_event_pipe(VmnetCommonState *s);

static void vmnet_send(void *opaque);

static void vmnet_send_stub(void *opaque);

static void vmnet_writable(void *opaque);

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
        ^(vmnet_return_t status, xpc_object_t interface_param) {
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

    vmnet_bufs_init(s);

    vmnet_create_event_pipe(s);
    vmnet_read_poll(nc, true);

    return 0;
}

void vmnet_poll_common(NetClientState *nc, bool enable)
{
    vmnet_read_poll(nc, enable);
    vmnet_write_poll(nc, enable);
}


ssize_t vmnet_receive_iov_common(NetClientState *nc,
                                 const iovec_t *iov,
                                 int iovcnt)
{
    VmnetCommonState *s;
    vmpktdesc_t packet;
    int pkt_cnt;
    int iov_no;
    vmnet_return_t if_status;

    s = DO_UPCAST(VmnetCommonState, nc, nc);

    packet.vm_pkt_iovcnt = iovcnt;
    packet.vm_flags = 0;
    packet.vm_pkt_size = 0;
    for (iov_no = 0; iov_no < iovcnt; ++iov_no) {
        packet.vm_pkt_size += iov[iov_no].iov_len;
    }

    if (packet.vm_pkt_size > s->max_packet_size) {
        warn_report("vmnet: packet is too big, %zu > %llu\n",
                    packet.vm_pkt_size,
                    s->max_packet_size);
        return -1;
    }

    packet.vm_pkt_iov = g_new0(iovec_t, iovcnt);
    memcpy(packet.vm_pkt_iov, iov, iovcnt * sizeof(iovec_t));

    pkt_cnt = 1;
    if_status = vmnet_write(s->vmnet_if, &packet, &pkt_cnt);

    if (if_status != VMNET_SUCCESS) {
        error_report("vmnet: write error: %s\n",
                     vmnet_status_map_str(if_status));
    }

    g_free(packet.vm_pkt_iov);
    if (if_status == VMNET_SUCCESS && pkt_cnt) {
        return packet.vm_pkt_size;
    }
    return 0;
}

void vmnet_cleanup_common(NetClientState *nc)
{
    VmnetCommonState *s;
    dispatch_queue_t if_destroy_q;

    s = DO_UPCAST(VmnetCommonState, nc, nc);

    qemu_purge_queued_packets(nc);
    vmnet_read_poll(nc, false);
    vmnet_write_poll(nc, false);

    if (s->vmnet_if == NULL) {
        return;
    }

    if_destroy_q = dispatch_queue_create(
        "org.qemu.vmnet.destroy",
        DISPATCH_QUEUE_SERIAL
    );

    vmnet_stop_interface(
        s->vmnet_if,
        if_destroy_q,
        ^(vmnet_return_t status) {
        });


    for (int i = 0; i < VMNET_PACKETS_LIMIT; ++i) {
        g_free(s->iov_buf[i].iov_base);
    }
}

static void vmnet_bufs_init(VmnetCommonState *s)
{
    int i;
    vmpktdesc_t *packets;
    iovec_t *iov;

    packets = s->packets_buf;
    iov = s->iov_buf;

    for (i = 0; i < VMNET_PACKETS_LIMIT; ++i) {
        iov[i].iov_len = s->max_packet_size;
        iov[i].iov_base = g_malloc0(iov[i].iov_len);
        packets[i].vm_pkt_iov = iov + i;
    }
}

static void vmnet_create_event_pipe(VmnetCommonState *s)
{
    dispatch_queue_t pkt_avail_q;
    assert(s->vmnet_if != NULL);

    pkt_avail_q = dispatch_queue_create(
        "org.qemu.vmnet.pkt_avail",
        DISPATCH_QUEUE_SERIAL
    );

    pipe(s->event_pipe_fd);
    fcntl(s->event_pipe_fd[0], F_SETFL, O_NONBLOCK);

    vmnet_interface_set_event_callback(
        s->vmnet_if,
        VMNET_INTERFACE_PACKETS_AVAILABLE,
        pkt_avail_q,
        ^(interface_event_t event_id, xpc_object_t event) {
          uint8_t dummy_byte;
          write(s->event_pipe_fd[1], &dummy_byte, 1);
        });
}

static void vmnet_send(void *opaque)
{
    NetClientState *nc;
    VmnetCommonState *s;

    iovec_t *iov;
    vmpktdesc_t *packets;
    int pkt_cnt;
    int i;

    vmnet_return_t if_status;
    ssize_t size;

    nc = opaque;
    s = DO_UPCAST(VmnetCommonState, nc, nc);
    vmnet_send_stub(opaque);

    pkt_cnt = VMNET_PACKETS_LIMIT;
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
        return;
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

static void vmnet_send_stub(void *opaque)
{
    NetClientState *nc = opaque;
    VmnetCommonState *s = DO_UPCAST(VmnetCommonState, nc, nc);

    uint8_t dummy_byte;
    while (read(s->event_pipe_fd[0], &dummy_byte, 1) > 0);
}

static void vmnet_writable(void *opaque)
{
    VmnetCommonState *s = opaque;
    vmnet_write_poll(&s->nc, false);
    qemu_flush_queued_packets(&s->nc);
}

static void vmnet_update_fd_handler(VmnetCommonState *s)
{
    qemu_set_fd_handler(s->event_pipe_fd[0],
                        s->read_poll ? vmnet_send : vmnet_send_stub,
                        s->write_poll ? vmnet_writable : NULL,
                        s);
}

static void vmnet_read_poll(NetClientState *nc, bool enable)
{
    VmnetCommonState *s = DO_UPCAST(VmnetCommonState, nc, nc);
    s->read_poll = enable;
    vmnet_update_fd_handler(s);
}

static void vmnet_write_poll(NetClientState *nc, bool enable)
{
    VmnetCommonState *s = DO_UPCAST(VmnetCommonState, nc, nc);
    s->write_poll = enable;
    vmnet_update_fd_handler(s);
}

static void vmnet_send_completed(NetClientState *nc, ssize_t len)
{
    vmnet_read_poll(nc, true);
}
