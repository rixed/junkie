// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef NETBIOS_H
#define NETBIOS_H
#include <junkie/proto/proto.h>

/** @file
 * @brief Netbios informations
 */

extern struct proto *proto_netbios;

struct netbios_proto_info {
    struct proto_info info;
};

void netbios_init(void);
void netbios_fini(void);

#endif
