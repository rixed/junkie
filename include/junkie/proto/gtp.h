// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef GTP_H_180123
#define GTP_H_180123
#include <junkie/proto/proto.h>

/** @file
 * @brief GTP informations
 */

extern struct proto *proto_gtp;

/// GTP message
struct gtp_proto_info {
    struct proto_info info;
};

void gtp_init(void);
void gtp_fini(void);

#endif
