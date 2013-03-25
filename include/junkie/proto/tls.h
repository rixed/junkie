// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef TLS_H_130325
#define TLS_H_130325
#include <junkie/proto/proto.h>

/** @file
 * @brief TLS informations
 */

extern struct proto *proto_tls;

struct tls_proto_info {
    struct proto_info info;
};

void tls_init(void);
void tls_fini(void);
#endif
