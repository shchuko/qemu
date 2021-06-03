/*
 * vmnet_int.h
 *
 * Copyright(c) 2021 Vladislav Yaroshchuk <yaroshchuk2000@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */
#ifndef VMNET_INT_H
#define VMNET_INT_H

#include "qemu/osdep.h"
#include "vmnet_int.h"
#include "clients.h"

#include <vmnet/vmnet.h>

#define VMNET_PACKETS_LIMIT 50

typedef struct VmnetCommonState {
  NetClientState nc;
  interface_ref vmnet_if;

  /* vmnet interface is ready to receive packages from qemu */
  bool write_poll;

  /* qemu is ready to receive packages from vmnet */
  bool read_poll;

  uint64_t mtu;
  uint64_t max_packet_size;

  struct vmpktdesc *packets_buf;
  struct iovec *iov_buf;

  dispatch_queue_t avail_pkt_q;
} VmnetCommonState;

const char *vmnet_status_map_str(vmnet_return_t status);

int vmnet_if_create(NetClientState *nc,
                    xpc_object_t if_desc,
                    Error **errp,
                    void (*completion_callback)(xpc_object_t interface_param));

bool vmnet_can_receive_common(NetClientState *nc);

ssize_t vmnet_receive_iov_common(NetClientState *nc,
                                 const struct iovec *iov,
                                 int iovcnt);


#endif /* VMNET_INT_H */
