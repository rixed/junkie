// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2010, SecurActive.
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
#include <stdbool.h>
#include "junkie/cpp.h"
#include "junkie/tools/log.h"
#include "junkie/tools/miscmacs.h"
#include "junkie/tools/objalloc.h"
#include "junkie/tools/mutex.h"
#include "junkie/tools/queue.h"
#include "junkie/proto/serialize.h"
#include "junkie/proto/proto.h"
#include "junkie/proto/ip.h"
#include "junkie/proto/eth.h"
#include "junkie/proto/erspan.h"

#undef LOG_CAT
#define LOG_CAT proto_erspan_log_category

LOG_CATEGORY_DEF(proto_erspan);

/*
 * Proto Infos
 */

static char const *erspan_direction_2_str(enum erspan_direction d)
{
    switch (d) {
        case ERSPAN_INCOMING: return "incoming";
        case ERSPAN_OUTGOING: return "outgoing";
    }
    assert(!"Invalid direction");
}

static void const *erspan_info_addr(struct proto_info const *info_, size_t *size)
{
    struct erspan_proto_info const *info = DOWNCAST(info_, info, erspan_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *erspan_info_2_str(struct proto_info const *info_)
{
    struct erspan_proto_info const *info = DOWNCAST(info_, info, erspan_proto_info);
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "%s, version=%"PRIu8", vlan=%"PRIu16", priority=%"PRIu8", direction=%s, truncated=%s, span_id=%"PRIu16,
        proto_info_2_str(info_),
        info->version,
        info->vlan,
        info->priority,
        erspan_direction_2_str(info->direction),
        info->truncated ? "yes":"no",
        info->span_id);
    return str;
}

static void erspan_serialize(struct proto_info const *info_, uint8_t **buf)
{
    struct erspan_proto_info const *info = DOWNCAST(info_, info, erspan_proto_info);
    proto_info_serialize(info_, buf);
    serialize_2(buf, info->vlan);
    serialize_2(buf, info->span_id);
    serialize_1(buf, info->version);
    serialize_1(buf, info->priority);
    serialize_1(buf, info->direction);
    serialize_1(buf, info->truncated);
}

static void erspan_deserialize(struct proto_info *info_, uint8_t const **buf)
{
    struct erspan_proto_info *info = DOWNCAST(info_, info, erspan_proto_info);
    proto_info_deserialize(info_, buf);
    info->vlan = deserialize_2(buf);
    info->span_id = deserialize_2(buf);
    info->version = deserialize_1(buf);
    info->priority = deserialize_1(buf);
    info->direction = deserialize_1(buf);
    info->truncated = deserialize_1(buf);
}

static void erspan_proto_info_ctor(struct erspan_proto_info *info, struct parser *parser, struct proto_info *parent, size_t payload, uint16_t vlan, uint16_t span_id, uint8_t version, uint8_t priority, enum erspan_direction dir, bool truncated)
{
    proto_info_ctor(&info->info, parser, parent, 8, payload);
    info->vlan = vlan;
    info->span_id = span_id;
    info->version = version;
    info->priority = priority;
    info->direction = dir;
    info->truncated = truncated;
}

/*
 * Parse
 */

static struct parser *erspan_subparser;

static enum proto_parse_status erspan_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    // Sanity checks
    if (wire_len < 8) {
        SLOG(LOG_DEBUG, "Bogus ERSPAN packet: shorter than ERSPAN header (%zu < 8)", wire_len);
        return PROTO_PARSE_ERR;
    }
    if (cap_len < 8) {
        return PROTO_TOO_SHORT;
    }

    // Parse
    uint16_t const vlan = ((packet[0] & 0xf) << 8) | packet[1];
    uint16_t const version = packet[0] >> 4;
    uint8_t const priority = packet[2] >> 5;
    uint8_t const dir = (packet[2] & 8) ? ERSPAN_OUTGOING : ERSPAN_INCOMING;
    uint8_t const truncated = !!(packet[2] & 4);
    uint16_t span_id = ((packet[2] & 3) << 8) | packet[3];

    struct erspan_proto_info info;
    erspan_proto_info_ctor(&info, parser, parent, wire_len - 8, vlan, span_id, version, priority, dir, truncated);

    if (! erspan_subparser) return PROTO_OK;

    enum proto_parse_status status = proto_parse(erspan_subparser, &info.info, way, packet + 8, cap_len - 8, wire_len - 8, now, tot_cap_len, tot_packet);
    if (status == PROTO_OK) return PROTO_OK;

    (void)proto_parse(NULL, &info.info, way, packet + 8, cap_len - 8, wire_len - 8, now, tot_cap_len, tot_packet);
    return PROTO_OK;
}

/*
 * Construction/Destruction
 */

static struct uniq_proto uniq_proto_erspan;
struct proto *proto_erspan = &uniq_proto_erspan.proto;
static struct eth_subproto erspan_eth_subproto;

void erspan_init(void)
{
    log_category_proto_erspan_init();
    erspan_subparser = proto_eth->ops->parser_new(proto_eth);
    if (! erspan_subparser) {
        SLOG(LOG_ERR, "Cannot spawn Eth parser for ERSPAN");
        // so be it
    }

    static struct proto_ops const ops = {
        .parse       = erspan_parse,
        .parser_new  = uniq_parser_new,
        .parser_del  = uniq_parser_del,
        .info_2_str  = erspan_info_2_str,
        .info_addr   = erspan_info_addr,
        .serialize   = erspan_serialize,
        .deserialize = erspan_deserialize,
    };
    uniq_proto_ctor(&uniq_proto_erspan, &ops, "ERSPAN", PROTO_CODE_ERSPAN);
    eth_subproto_ctor(&erspan_eth_subproto, ETH_PROTO_ERSPAN, proto_erspan);
}

void erspan_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    eth_subproto_dtor(&erspan_eth_subproto);
    parser_unref(&erspan_subparser);
    uniq_proto_dtor(&uniq_proto_erspan);
#   endif
    log_category_proto_erspan_fini();
}
