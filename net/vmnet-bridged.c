/*
 * vmnet-bridged.c
 *
 * Copyright(c) 2021 Vladislav Yaroshchuk <yaroshchuk2000@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qapi-types-net.h"
#include "vmnet_int.h"
#include "clients.h"
#include "qemu/error-report.h"
#include "qapi/error.h"

#include <vmnet/vmnet.h>

int net_init_vmnet_bridged(const Netdev *netdev, const char *name,
                           NetClientState *peer, Error **errp)
{
  error_setg(errp, "vmnet-bridged is not implemented yet");
  return -1;
}
