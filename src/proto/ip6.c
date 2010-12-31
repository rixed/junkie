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
#include <junkie/cpp.h>
#include <junkie/tools/log.h>
#include <junkie/tools/miscmacs.h>
#include <junkie/proto/proto.h>
#include <junkie/proto/eth.h>
#include <junkie/proto/ip.h>
#include "proto/ip_hdr.h"

static char const Id[] = "$Id: c1c50fb3b93381abf716bfa300605c930e937160 $";

#undef LOG_CAT
#define LOG_CAT proto_ip_log_category

#define IP6_TIMEOUT (60*60)
#define IP6_HASH_SIZE 10000

/*
 * Proto Infos (only the info ctor is different from ipv4
 */

static void ip6_proto_info_ctor(struct ip_proto_info *info, struct parser *parser, struct proto_info const *parent, size_t head_len, size_t payload, unsigned version, struct ipv6_hdr const *iphdr)
{
    proto_info_ctor(&info->info, parser, parent, head_len, payload);

    info->version = version;
    ip_addr_ctor_from_ip6(&info->key.addr[0], &iphdr->src);
    ip_addr_ctor_from_ip6(&info->key.addr[1], &iphdr->dst);
    info->key.protocol = iphdr->next;
    info->ttl = iphdr->hop_limit;
}

/*
 * Subproto management
 */

static LIST_HEAD(ip6_subprotos, ip_subproto) ip6_subprotos;

void ip6_subproto_ctor(struct ip_subproto *ip_subproto, unsigned protocol, struct proto *proto)
{
    SLOG(LOG_DEBUG, "Adding proto %s for protocol value %u", proto->name, protocol);
    ip_subproto->protocol = protocol;
    ip_subproto->proto = proto;
    LIST_INSERT_HEAD(&ip6_subprotos, ip_subproto, entry);
}

void ip6_subproto_dtor(struct ip_subproto *ip_subproto)
{
    SLOG(LOG_DEBUG, "Removing proto %s for protocol value %u", ip_subproto->proto->name, ip_subproto->protocol);
    LIST_REMOVE(ip_subproto, entry);
}

/*
 * Parse
 */

static enum proto_parse_status ip6_parse(struct parser *parser, struct proto_info const *parent, unsigned unused_ way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn)
{
    struct mux_parser *mux_parser = DOWNCAST(parser, parser, mux_parser);
    struct ipv6_hdr const *iphdr = (struct ipv6_hdr *)packet;
    size_t const iphdr_len = sizeof(*iphdr);

    // Sanity checks

    if (wire_len < iphdr_len) {
        SLOG(LOG_DEBUG, "Bogus IPv6 packet : %zu < %zu", wire_len, iphdr_len);
        return PROTO_PARSE_ERR;
    }

    if (cap_len < iphdr_len) return PROTO_TOO_SHORT;

    SLOG(LOG_DEBUG, "New packet of %zu bytes, proto %"PRIu8", %"PRINIPQUAD6"->%"PRINIPQUAD6,
        wire_len, iphdr->next, NIPQUAD6(&iphdr->src), NIPQUAD6(&iphdr->dst));

    size_t const payload = ntohs(iphdr->payload_len);
    size_t const ip_len = iphdr_len + payload;
    if (ip_len > wire_len) {
        SLOG(LOG_DEBUG, "Bogus IPv6 total length : %zu > %zu", ip_len, wire_len);
        return PROTO_PARSE_ERR;
    }

    unsigned const version = iphdr->version;
    if (version != 6) {
        SLOG(LOG_DEBUG, "Bogus IPv6 version : %u instead of 6", version);
        return PROTO_PARSE_ERR;
    }

    // Parse

    struct ip_proto_info info;
    ip6_proto_info_ctor(&info, parser, parent, iphdr_len, payload, version, iphdr);

    // Parse payload

    struct mux_subparser *subparser = NULL;
    unsigned way2 = 0;
    struct ip_subproto *subproto;
    LIST_FOREACH(subproto, &ip6_subprotos, entry) {
        if (subproto->protocol == info.key.protocol) {
            struct ip_key subparser_key;
            way2 = ip_key_ctor(&subparser_key, info.key.protocol, info.key.addr+0, info.key.addr+1);
            subparser = mux_subparser_lookup(mux_parser, subproto->proto, NULL, &subparser_key, now);
            break;
        }
    }
    if (! subparser) {
        SLOG(LOG_DEBUG, "IPv6 protocol %u unknown", info.key.protocol);
        goto fallback;
    }

    if (0 != proto_parse(subparser->parser, &info.info, way2, packet + iphdr_len, cap_len - iphdr_len, wire_len - iphdr_len, now, okfn)) goto fallback;
    return PROTO_OK;

fallback:
    (void)proto_parse(NULL, &info.info, way2, packet + iphdr_len, cap_len - iphdr_len, wire_len - iphdr_len, now, okfn);
    return PROTO_OK;
}

/*
 * Construction/Destruction
 */

static struct mux_proto mux_proto_ip6;
struct proto *proto_ip6 = &mux_proto_ip6.proto;
static struct eth_subproto eth_subproto;

void ip6_init(void)
{
    static struct proto_ops const ops = {
        .parse = ip6_parse,
        .parser_new = mux_parser_new,
        .parser_del = mux_parser_del,
        .info_2_str = ip_info_2_str,
    };
    mux_proto_ctor(&mux_proto_ip6, &ops, &mux_proto_ops, "IPv6", IP6_TIMEOUT, sizeof(struct ip_key), IP6_HASH_SIZE);
    eth_subproto_ctor(&eth_subproto, ETH_PROTO_IPv6, proto_ip6);
    LIST_INIT(&ip6_subprotos);
}

void ip6_fini(void)
{
    assert(LIST_EMPTY(&ip6_subprotos));
    eth_subproto_dtor(&eth_subproto);
    mux_proto_dtor(&mux_proto_ip6);
}
