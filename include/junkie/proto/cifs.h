// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef CIFS_H_101221
#define CIFS_H_101221
#include <junkie/proto/proto.h>

/** @file
 * @brief CIFS informations
 */

extern struct proto *proto_cifs;

struct cifs_proto_info {
    struct proto_info info;
    unsigned command;
    uint32_t status;
};

void cifs_init(void);
void cifs_fini(void);

#endif
