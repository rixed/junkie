// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef VXLAN_H_190218
#define VXLAN_H_190218
#include <inttypes.h>
#include <stdbool.h>
#include <junkie/proto/proto.h>

/** @file
 * @brief VXLAN informations
 */

#define VXLAN_PORT 4789

extern struct proto *proto_vxlan;

struct vxlan_proto_info {
    struct proto_info info;                 ///< Header and payload sizes
    uint32_t vni;
    uint16_t group_policy_id;
    uint8_t gbp_extension:1;
    uint8_t vni_set:1;
    uint8_t dont_learn:1;
    uint8_t policy_applied:1;
};

void vxlan_init(void);
void vxlan_fini(void);

#endif
