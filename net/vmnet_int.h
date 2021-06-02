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

typedef struct VmnetCommonState {
  NetClientState nc;
  bool vmnet_link_up;
  bool ready_to_receive;


  uint64_t mtu;
  uint64_t max_packet_size;

} VmnetCommonState;


#endif /* VMNET_INT_H */
