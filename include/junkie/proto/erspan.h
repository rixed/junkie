// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef ERSPAN_H_100402
#define ERSPAN_H_100402
#include <inttypes.h>
#include <junkie/proto/proto.h>

/** @file
 * @brief ERSPAN informations
 */

extern struct proto *proto_erspan;

/// ERSPAN encapsulation
struct erspan_proto_info {
    struct proto_info info;                 ///< Header and payload sizes
    uint16_t vlan;
    uint16_t span_id;
    uint8_t version;
    uint8_t priority;
    enum erspan_direction { ERSPAN_INCOMING=0, ERSPAN_OUTGOING=1 } direction;
    bool truncated;
};

void erspan_init(void);
void erspan_fini(void);

#endif
