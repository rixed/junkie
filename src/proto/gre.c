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
#include "junkie/proto/gre.h"

#undef LOG_CAT
#define LOG_CAT proto_gre_log_category

// TODO: optionally use the key in the flow id

LOG_CATEGORY_DEF(proto_gre);

// Description of a GRE header
struct gre_hdr {
    uint8_t flags;
#   define GRE_CHECKSUM_MASK    0x01
#   define GRE_ROUTING_MASK     0x02
#   define GRE_KEY_MASK         0x04
#   define GRE_SEQNUM_MASK      0x08
#   define GRE_STRICTROUTE_MASK 0x10
    uint8_t version_flags;
#   define GRE_VERSION_MASK     0xe0
    uint16_t protocol;
} packed_;

/*
 * Proto Infos
 */

static void const *gre_info_addr(struct proto_info const *info_, size_t *size)
{
    struct gre_proto_info const *info = DOWNCAST(info_, info, gre_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *gre_info_2_str(struct proto_info const *info_)
{
    struct gre_proto_info const *info = DOWNCAST(info_, info, gre_proto_info);
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "%s, version=%"PRIu8", protocol=%"PRIu16", key=%s",
        proto_info_2_str(info_),
        info->version,
        info->protocol,
        info->set_values & GRE_KEY_SET ? tempstr_printf("%"PRIu32, info->key) : "None");
    return str;
}

static void gre_serialize(struct proto_info const *info_, uint8_t **buf)
{
    struct gre_proto_info const *info = DOWNCAST(info_, info, gre_proto_info);
    proto_info_serialize(info_, buf);
    serialize_1(buf, info->set_values);
    if (info->set_values & GRE_KEY_SET) serialize_4(buf, info->key);
    serialize_2(buf, info->protocol);
    serialize_1(buf, info->version);
}

static void gre_deserialize(struct proto_info *info_, uint8_t const **buf)
{
    struct gre_proto_info *info = DOWNCAST(info_, info, gre_proto_info);
    proto_info_deserialize(info_, buf);
    info->set_values = deserialize_1(buf);
    if (info->set_values & GRE_KEY_SET) info->key = deserialize_4(buf);
    info->protocol = deserialize_2(buf);
    info->version = deserialize_1(buf);
}

static void gre_proto_info_ctor(struct gre_proto_info *info, struct parser *parser, struct proto_info *parent, size_t head_len, size_t payload, uint16_t proto, uint8_t version, bool key_set, uint32_t key)
{
    proto_info_ctor(&info->info, parser, parent, head_len, payload);
    info->set_values = key_set ? GRE_KEY_SET : 0;
    info->key = key_set ? key : 0;
    info->protocol = proto;
    info->version = version;
}

/*
 * GRE subparsers
 */

struct gre_subparser {
    LIST_ENTRY(gre_subparser) entry;
    uint16_t protocol;
    struct parser *parser;
};

static LIST_HEAD(gre_subparsers, gre_subparser) gre_subparsers;
static struct mutex gre_subparsers_mutex;

static void gre_subparser_ctor(struct gre_subparser *gre_subparser, uint16_t protocol, struct parser *parser)
{
    gre_subparser->parser = parser_ref(parser);
    gre_subparser->protocol = protocol;
    mutex_lock(&gre_subparsers_mutex);
    LIST_INSERT_HEAD(&gre_subparsers, gre_subparser, entry);
    mutex_unlock(&gre_subparsers_mutex);
}

static struct gre_subparser *gre_subparser_new(uint16_t protocol, struct parser *parser)
{
    struct gre_subparser *gre_subparser = objalloc_nice(sizeof(*gre_subparser), "GRE subparser");
    if (! gre_subparser) {
        return NULL;
    }
    gre_subparser_ctor(gre_subparser, protocol, parser);
    return gre_subparser;
}

static void gre_subparser_dtor(struct gre_subparser *gre_subparser)
{
    mutex_lock(&gre_subparsers_mutex);
    LIST_REMOVE(gre_subparser, entry);
    mutex_unlock(&gre_subparsers_mutex);
    parser_unref(&gre_subparser->parser);
}

static void gre_subparser_del(struct gre_subparser *gre_subparser)
{
    gre_subparser_dtor(gre_subparser);
    objfree(gre_subparser);
}

/*
 * Parse
 */

static enum proto_parse_status gre_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct gre_hdr const *grehdr = (struct gre_hdr *)packet;
    size_t grehdr_len = sizeof(*grehdr);

    // Sanity checks
    if (wire_len < grehdr_len) {
        SLOG(LOG_DEBUG, "Bogus GRE packet: shorter than GRE header (%zu < %zu)", wire_len, grehdr_len);
        return PROTO_PARSE_ERR;
    }

    if (cap_len < grehdr_len) {
        SLOG(LOG_DEBUG, "Too short on data (%zu < %zu)", cap_len, grehdr_len);
        return PROTO_TOO_SHORT;
    }

    // Parse
    uint16_t const h_proto = READ_U16N(&grehdr->protocol);
    uint8_t const flags = READ_U8(&grehdr->flags);
    // FIXME: test me!
    size_t h_len = sizeof(*grehdr) +
        // if either checksum or routing flag are set then both checksum and routing fields are present
        (flags & (GRE_CHECKSUM_MASK|GRE_ROUTING_MASK) ? 4 : 0) +
        (flags & GRE_KEY_MASK ? 4 : 0) +
        (flags & GRE_SEQNUM_MASK ? 4 : 0);
        // TODO: support for older GRE with source routing ?

    if (wire_len < h_len) {
        SLOG(LOG_DEBUG, "Bogus GRE packet: too short (%zu < %zu)", wire_len, h_len);
        return PROTO_PARSE_ERR;
    }

    if (cap_len < h_len) {
        SLOG(LOG_DEBUG, "Too short on data for full header (%zu < %zu)", cap_len, h_len);
        return PROTO_TOO_SHORT;
    }

    uint8_t const version = (READ_U8(&grehdr->version_flags) & GRE_VERSION_MASK) >> 5U;
    uint32_t const key = flags & GRE_KEY_MASK ?
        READ_U32N((char const *)(grehdr+1) + (flags & (GRE_CHECKSUM_MASK|GRE_ROUTING_MASK) ? 4 : 0)) : 0;

    struct gre_proto_info info;
    gre_proto_info_ctor(&info, parser, parent, h_len, wire_len - h_len, h_proto, version, flags & GRE_KEY_MASK ? true : false, key);

    // Do we already have a parser for this one ?
    struct gre_subparser *gre_subparser;
    struct parser *subparser = NULL;
    LIST_LOOKUP_LOCKED(gre_subparser, &gre_subparsers, entry, gre_subparser->protocol == h_proto, &gre_subparsers_mutex);
    if (gre_subparser) subparser = parser_ref(gre_subparser->parser);

    if (! gre_subparser) {  // Nope, look for the proto
        struct proto *sub_proto = eth_subproto_lookup(h_proto);
        if (! sub_proto) {  // we don't care, skip payload
            goto fallback;
        }
        subparser = sub_proto->ops->parser_new(sub_proto);
        if (! subparser) goto fallback;

        // Remember it for next occurrence
        gre_subparser = gre_subparser_new(h_proto, subparser);
        if (! gre_subparser) {
            parser_unref(&subparser);
            goto fallback;
        }
    }

    assert(subparser);
    enum proto_parse_status status = proto_parse(subparser, &info.info, way, packet + h_len, cap_len - h_len, wire_len - h_len, now, tot_cap_len, tot_packet);
    parser_unref(&subparser);

    if (status == PROTO_OK) return PROTO_OK;

fallback:
    (void)proto_parse(NULL, &info.info, way, packet + h_len, cap_len - h_len, wire_len - h_len, now, tot_cap_len, tot_packet);
    return PROTO_OK;
}

/*
 * Construction/Destruction
 */

static struct uniq_proto uniq_proto_gre;
struct proto *proto_gre = &uniq_proto_gre.proto;
struct ip_subproto ip_subproto, ip6_subproto;

void gre_init(void)
{
    log_category_proto_gre_init();
    mutex_ctor(&gre_subparsers_mutex, "GRE subparsers");
    LIST_INIT(&gre_subparsers);

    static struct proto_ops const ops = {
        .parse       = gre_parse,
        .parser_new  = uniq_parser_new,
        .parser_del  = uniq_parser_del,
        .info_2_str  = gre_info_2_str,
        .info_addr   = gre_info_addr,
        .serialize   = gre_serialize,
        .deserialize = gre_deserialize,
    };
    uniq_proto_ctor(&uniq_proto_gre, &ops, "GRE", PROTO_CODE_GRE);
    ip_subproto_ctor(&ip_subproto, IPPROTO_GRE, proto_gre);
    ip6_subproto_ctor(&ip6_subproto, IPPROTO_GRE, proto_gre);
}

void gre_fini(void)
{
    ip6_subproto_dtor(&ip6_subproto);
    ip_subproto_dtor(&ip_subproto);

    struct gre_subparser *gre_subparser;
    while (NULL != (gre_subparser = LIST_FIRST(&gre_subparsers))) {
        gre_subparser_del(gre_subparser);
    }

    uniq_proto_dtor(&uniq_proto_gre);
    mutex_dtor(&gre_subparsers_mutex);
    log_category_proto_gre_fini();
}
