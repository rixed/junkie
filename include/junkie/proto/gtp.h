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
    unsigned version:3;
    unsigned msg_type:8;
#   define GTP_HAS_TEID        0x0001  // GTPv2 might have no TEID
#   define GTP_HAS_SEQNUM      0x0002
#   define GTP_HAS_NPDU_NUMBER 0x0004
    unsigned set_values;
    uint32_t teid;
    uint16_t seqnum;
    uint8_t npdu_number;
};

void gtp_init(void);
void gtp_fini(void);

#endif
