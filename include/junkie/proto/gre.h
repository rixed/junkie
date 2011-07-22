// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef GRE_H_100402
#define GRE_H_100402
#include <inttypes.h>
#include <junkie/proto/proto.h>
#include <junkie/tools/queue.h>

/** @file
 * @brief GRE informations
 */

extern struct proto *proto_gre;

/// GRE encapsulation
struct gre_proto_info {
    struct proto_info info;                 ///< Header and payload sizes
#   define GRE_KEY_SET 0x1
    unsigned set_values;
    uint32_t key;
    uint16_t protocol;                      ///< Eth protocol (note: we use the same subproto information than the ethernet parser)
    uint8_t version;
};

void gre_init(void);
void gre_fini(void);

#endif
