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
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include "junkie/cpp.h"
#include "junkie/tools/log.h"
#include "junkie/tools/miscmacs.h"
#include "junkie/proto/proto.h"
#include "junkie/proto/eth.h"
#include "junkie/proto/ip.h"
#include "proto/ip_hdr.h"

#undef LOG_CAT
#define LOG_CAT proto_ip_log_category

#define IP6_HASH_SIZE 30011 /* See ip.c */

/*
 * Proto Infos (only the info ctor is different from ipv4
 */

static void ip6_proto_info_ctor(struct ip_proto_info *info, struct parser *parser, struct proto_info *parent, size_t head_len, size_t payload, unsigned version, struct ipv6_hdr const *iphdr)
{
    proto_info_ctor(&info->info, parser, parent, head_len, payload);

    info->version = version;
    ip_addr_ctor_from_ip6(&info->key.addr[0], &iphdr->src);
    ip_addr_ctor_from_ip6(&info->key.addr[1], &iphdr->dst);
    info->key.protocol = READ_U8(&iphdr->next);
    info->ttl = READ_U8(&iphdr->hop_limit);
    info->way = 0;  // will be set later
    info->traffic_class = (READ_U8(&iphdr->version_class) << 4) | (READ_U8(&iphdr->flow[0]) >> 4);
    info->id = ((READ_U8(&iphdr->flow[0]) & 0x0f) << 16U) | READ_U16N(&iphdr->flow[1]);
}

/*
 * Subproto management
 */

static LIST_HEAD(ip6_subprotos, ip_subproto) ip6_subprotos;
static struct mutex ip6_subprotos_mutex;

void ip6_subproto_ctor(struct ip_subproto *ip_subproto, unsigned protocol, struct proto *proto)
{
    SLOG(LOG_DEBUG, "Adding proto %s for protocol value %u", proto->name, protocol);
    ip_subproto->protocol = protocol;
    ip_subproto->proto = proto;
    mutex_lock(&ip6_subprotos_mutex);
    LIST_INSERT_HEAD(&ip6_subprotos, ip_subproto, entry);
    mutex_unlock(&ip6_subprotos_mutex);
}

void ip6_subproto_dtor(struct ip_subproto *ip_subproto)
{
    SLOG(LOG_DEBUG, "Removing proto %s for protocol value %u", ip_subproto->proto->name, ip_subproto->protocol);
    mutex_lock(&ip6_subprotos_mutex);
    LIST_REMOVE(ip_subproto, entry);
    mutex_unlock(&ip6_subprotos_mutex);
}

/*
 * Parse
 */

enum proto_parse_status ip6_parse(struct parser *parser, struct proto_info *parent, unsigned unused_ way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct mux_parser *mux_parser = DOWNCAST(parser, parser, mux_parser);
    struct ipv6_hdr const *iphdr = (struct ipv6_hdr *)packet;
    size_t const iphdr_len = sizeof(*iphdr);

    // Sanity checks

    if (wire_len < iphdr_len) {
        SLOG(LOG_DEBUG, "Bogus IPv6 packet: %zu < %zu", wire_len, iphdr_len);
        return PROTO_PARSE_ERR;
    }

    if (cap_len < iphdr_len) return PROTO_TOO_SHORT;

    unsigned const next = READ_U8(&iphdr->next);
    size_t const payload = READ_U16N(&iphdr->payload_len);
    size_t const ip_len = iphdr_len + payload;
    size_t const cap_payload = MIN(cap_len - iphdr_len, payload);
    unsigned const version = IP6_VERSION(iphdr);

    SLOG(LOG_DEBUG, "New packet of %zu bytes, proto %u, %"PRINIPQUAD6"->%"PRINIPQUAD6,
        ip_len, next, NIPQUAD6(&iphdr->src), NIPQUAD6(&iphdr->dst));

    if (ip_len > wire_len) {
        SLOG(LOG_DEBUG, "Bogus IPv6 total length: %zu > %zu", ip_len, wire_len);
        return PROTO_PARSE_ERR;
    }

    if (version != 6) {
        SLOG(LOG_DEBUG, "Bogus IPv6 version: %u instead of 6", version);
        return PROTO_PARSE_ERR;
    }

    // Parse

    struct ip_proto_info info;
    ip6_proto_info_ctor(&info, parser, parent, iphdr_len, payload, version, iphdr);

    // Parse payload

    struct mux_subparser *subparser = NULL;

    struct ip_subproto *subproto;
    LIST_LOOKUP_LOCKED(subproto, &ip6_subprotos, entry, subproto->protocol == info.key.protocol, &ip6_subprotos_mutex);
    if (subproto) {
        struct ip_key subparser_key;
        info.way = ip_key_ctor(&subparser_key, info.key.protocol, info.key.addr+0, info.key.addr+1);
        subparser = mux_subparser_lookup(mux_parser, subproto->proto, NULL, &subparser_key, now);
    }

    if (! subparser) {
        SLOG(LOG_DEBUG, "IPv6 protocol %u unknown", info.key.protocol);
        goto fallback;
    }

    enum proto_parse_status status = proto_parse(subparser->parser, &info.info, info.way, packet + iphdr_len, cap_payload, payload, now, tot_cap_len, tot_packet);
    mux_subparser_unref(&subparser);
    if (status == PROTO_OK) return PROTO_OK;

fallback:
    (void)proto_parse(NULL, &info.info, info.way, packet + iphdr_len, cap_payload, payload, now, tot_cap_len, tot_packet);
    return PROTO_OK;
}

/*
 * Construction/Destruction
 */

static struct mux_proto mux_proto_ip6;
struct proto *proto_ip6 = &mux_proto_ip6.proto;
static struct eth_subproto ip6_eth_subproto;
static struct ip_subproto ip6_ip_subproto;

void ip6_init(void)
{
    mutex_ctor(&ip6_subprotos_mutex, "IPv6 subprotocols");
    LIST_INIT(&ip6_subprotos);
    static struct proto_ops const ops = {
        .parse       = ip6_parse,
        .parser_new  = mux_parser_new,
        .parser_del  = mux_parser_del,
        .info_2_str  = ip_info_2_str,
        .info_addr   = ip_info_addr
    };
    mux_proto_ctor(&mux_proto_ip6, &ops, &mux_proto_ops, "IPv6", PROTO_CODE_IP6, sizeof(struct ip_key), IP6_HASH_SIZE);
    eth_subproto_ctor(&ip6_eth_subproto, ETH_PROTO_IPv6, proto_ip6);
    ip_subproto_ctor(&ip6_ip_subproto, IPPROTO_IPV6, proto_ip6);
}

void ip6_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    assert(LIST_EMPTY(&ip6_subprotos));
    ip_subproto_dtor(&ip6_ip_subproto);
    eth_subproto_dtor(&ip6_eth_subproto);
    mutex_dtor(&ip6_subprotos_mutex);
    mux_proto_dtor(&mux_proto_ip6);
#   endif
}
