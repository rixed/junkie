// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef DISCOVERY_H_120717
#define DISCOVERY_H_120717
#include <junkie/proto/proto.h>
#include <junkie/cpp.h>

/** @file
 * @brief Protocol discovery informations
 *
 * When we don't know a payload, we handle it to a protocol discovery virtual parser,
 * which can either:
 *
 * - don't know what to do with it neither
 * - discover that it's for a proto we actualy can parse (such as RTP for instance),
 *   thus pass it to the proper parser (and qualify the conntracker)
 * - discover that it's for a proto we do not parse, and append a new proto_info
 *   containing this discovery.
 */

extern struct proto *proto_discovery;

struct discovery_proto_info {
    struct proto_info info;
    struct discovery_protocol {
        enum discovery_trust {
            DISC_HIGH,
            DISC_MEDIUM,
            DISC_LOW,
        } trust;
        uint16_t id;
        char name[128];
    } protocol;
};

void discovery_init(void);
void discovery_fini(void);

#endif
