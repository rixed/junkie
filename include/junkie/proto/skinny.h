// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef SKINNY_H_130515
#define SKINNY_H_130515
#include <junkie/proto/proto.h>

/** @file
 * @brief Skinny informations
 */

extern struct proto *proto_skinny;

/// SKINNY message
struct skinny_proto_info {
    struct proto_info info;
};

void skinny_init(void);
void skinny_fini(void);

#endif
