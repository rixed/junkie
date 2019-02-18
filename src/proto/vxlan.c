// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2019, Securactive.
 *
 * This file is part of Junkie.
 *
 * Junkie is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Junkie is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Junkie.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "junkie/cpp.h"
#include "junkie/tools/log.h"
#include "junkie/tools/miscmacs.h"
#include "junkie/tools/objalloc.h"
#include "junkie/tools/mutex.h"
#include "junkie/tools/queue.h"
#include "junkie/proto/proto.h"
#include "junkie/proto/udp.h"
#include "junkie/proto/eth.h"
#include "junkie/proto/vxlan.h"

#undef LOG_CAT
#define LOG_CAT proto_vxlan_log_category

LOG_CATEGORY_DEF(proto_vxlan);

// VXLAN header
struct vxlan_hdr {
    uint16_t flags;
    uint16_t group_policy_id;
    uint32_t vni_reserved;
} packed_;

/*
 * Proto Infos
 */

static void const *vxlan_info_addr(struct proto_info const *info_, size_t *size)
{
    struct vxlan_proto_info const *info = DOWNCAST(info_, info, vxlan_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *vni_2_str(uint32_t vni)
{
    return tempstr_printf(", %"PRIu32, vni);
}

static char const *policy_2_str(uint16_t id)
{
    return tempstr_printf(", %"PRIu16, id);
}

static char const *vxlan_info_2_str(struct proto_info const *info_)
{
    struct vxlan_proto_info const *info = DOWNCAST(info_, info, vxlan_proto_info);
    return tempstr_printf("%s%s%s%s",
        proto_info_2_str(info_),
        info->vni_set ? vni_2_str(info->vni) : "",
        info->policy_applied ? policy_2_str(info->group_policy_id) : "",
        info->dont_learn ? ", do not learn" : "");
}

static void vxlan_proto_info_ctor(struct vxlan_proto_info *info, struct parser *parser, struct proto_info *parent, size_t hdr_len, size_t payload, uint32_t vni, uint16_t group_policy_id, uint16_t flags)
{
    proto_info_ctor(&info->info, parser, parent, hdr_len, payload);
    info->vni = vni;
    info->group_policy_id = group_policy_id;
    info->gbp_extension = flags & 0x80;
    info->vni_set = flags & 0x08;
    info->dont_learn = flags & 0x400;
    info->policy_applied = flags & 0x8000;
}

/*
 * VXLAN subparsers
 */

struct vxlan_subparser {
    LIST_ENTRY(vxlan_subparser) entry;
    uint32_t vni;
    struct parser *parser;
};

// TODO: Hash per VNI:
static LIST_HEAD(vxlan_subparsers, vxlan_subparser) vxlan_subparsers;
/* TODO: We may have many different subparsers in between the same VTEP that
 * will compete for this lock. Have an array of locks and use VNI as key? */
static struct mutex vxlan_subparsers_mutex;

static void vxlan_subparser_ctor(struct vxlan_subparser *vxlan_subparser, uint32_t vni, struct parser *parser)
{
    vxlan_subparser->parser = parser_ref(parser);
    vxlan_subparser->vni = vni;
    mutex_lock(&vxlan_subparsers_mutex);
    LIST_INSERT_HEAD(&vxlan_subparsers, vxlan_subparser, entry);
    mutex_unlock(&vxlan_subparsers_mutex);
}

static struct vxlan_subparser *vxlan_subparser_new(uint32_t vni, struct parser *parser)
{
    struct vxlan_subparser *vxlan_subparser = objalloc_nice(sizeof(*vxlan_subparser), "VXLAN subparser");
    if (! vxlan_subparser) {
        return NULL;
    }
    vxlan_subparser_ctor(vxlan_subparser, vni, parser);
    return vxlan_subparser;
}

#ifdef DELETE_ALL_AT_EXIT
static void vxlan_subparser_dtor(struct vxlan_subparser *vxlan_subparser)
{
    mutex_lock(&vxlan_subparsers_mutex);
    LIST_REMOVE(vxlan_subparser, entry);
    mutex_unlock(&vxlan_subparsers_mutex);
    parser_unref(&vxlan_subparser->parser);
}

static void vxlan_subparser_del(struct vxlan_subparser *vxlan_subparser)
{
    vxlan_subparser_dtor(vxlan_subparser);
    objfree(vxlan_subparser);
}
#endif

/*
 * Parse
 */

static enum proto_parse_status vxlan_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct vxlan_hdr const *vxlanhdr = (struct vxlan_hdr *)packet;
    size_t hdr_len = sizeof(*vxlanhdr);

    // Sanity checks
    if (wire_len < hdr_len) {
        SLOG(LOG_DEBUG, "Bogus VXLAN packet: shorter than VXLAN header (%zu < %zu)", wire_len, hdr_len);
        return PROTO_PARSE_ERR;
    }

    if (cap_len < hdr_len) {
        SLOG(LOG_DEBUG, "Too short on data (%zu < %zu)", cap_len, hdr_len);
        return PROTO_TOO_SHORT;
    }

    // Parse
    uint16_t const flags = READ_U16N(&vxlanhdr->flags);
    uint16_t const group_policy_id = READ_U16(&vxlanhdr->group_policy_id);
    uint32_t const vni = READ_U32(&vxlanhdr->vni_reserved) & 0xffffff00;
    SLOG(LOG_DEBUG, "VXLAN header for VNI: %"PRIu32, vni);

    struct vxlan_proto_info info;
    vxlan_proto_info_ctor(&info, parser, parent, hdr_len, wire_len - hdr_len, vni, group_policy_id, flags);

    // Do we already have a parser for this VNI?
    struct vxlan_subparser *vxlan_subparser;
    struct parser *subparser = NULL;
    LIST_LOOKUP_LOCKED(vxlan_subparser, &vxlan_subparsers, entry, vxlan_subparser->vni == vni, &vxlan_subparsers_mutex);
    if (vxlan_subparser) subparser = parser_ref(vxlan_subparser->parser);

    if (! vxlan_subparser) {  // Nope, create a new eth parser
        subparser = proto_eth->ops->parser_new(proto_eth);
        if (! subparser) goto fallback;

        // Remember it for next occurrence
        vxlan_subparser = vxlan_subparser_new(vni, subparser);
        if (! vxlan_subparser) {
            parser_unref(&subparser);
            goto fallback;
        }
    }

    assert(subparser);
    enum proto_parse_status status = proto_parse(subparser, &info.info, way, packet + hdr_len, cap_len - hdr_len, wire_len - hdr_len, now, tot_cap_len, tot_packet);
    parser_unref(&subparser);

    if (status == PROTO_OK) return PROTO_OK;

fallback:
    (void)proto_parse(NULL, &info.info, way, packet + hdr_len, cap_len - hdr_len, wire_len - hdr_len, now, tot_cap_len, tot_packet);
    return PROTO_OK;
}

/*
 * Construction/Destruction
 *
 * We assume all VTEP refer to the same VXLAN space and share a single
 * parser/subparser hash for all VXLAN traffic.
 */

static struct uniq_proto uniq_proto_vxlan;
struct proto *proto_vxlan = &uniq_proto_vxlan.proto;
static struct port_muxer vxlan_port_muxer;

void vxlan_init(void)
{
    log_category_proto_vxlan_init();
    mutex_ctor(&vxlan_subparsers_mutex, "VXLAN subparsers");
    LIST_INIT(&vxlan_subparsers);

    static struct proto_ops const ops = {
        .parse       = vxlan_parse,
        .parser_new  = uniq_parser_new,
        .parser_del  = uniq_parser_del,
        .info_2_str  = vxlan_info_2_str,
        .info_addr   = vxlan_info_addr
    };
    uniq_proto_ctor(&uniq_proto_vxlan, &ops, "VXLAN", PROTO_CODE_VXLAN);
    port_muxer_ctor(&vxlan_port_muxer, &udp_port_muxers, VXLAN_PORT, VXLAN_PORT, proto_vxlan);
}

void vxlan_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    port_muxer_dtor(&vxlan_port_muxer, &udp_port_muxers);

    struct vxlan_subparser *vxlan_subparser;
    while (NULL != (vxlan_subparser = LIST_FIRST(&vxlan_subparsers))) {
        vxlan_subparser_del(vxlan_subparser);
    }

    uniq_proto_dtor(&uniq_proto_vxlan);
    mutex_dtor(&vxlan_subparsers_mutex);
#   endif

    log_category_proto_vxlan_fini();
}
