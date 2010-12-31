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
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <junkie/cpp.h>
#include <junkie/tools/log.h>
#include <junkie/tools/miscmacs.h>
#include <junkie/tools/tempstr.h>
#include <junkie/proto/proto.h>
#include <junkie/proto/eth.h>
#include <junkie/proto/ip.h>
#include "proto/ip_hdr.h"

static char const Id[] = "$Id: 003ae93bbf458d21ffd9582b447feb9019b93405 $";

#undef LOG_CAT
#define LOG_CAT proto_ip_log_category

LOG_CATEGORY_DEC(proto_ip);
LOG_CATEGORY_DEF(proto_ip);

#define IP_TIMEOUT (60*60)
#define IP_HASH_SIZE 10000

/*
 * Proto Infos
 */

char const *ip_info_2_str(struct proto_info const *info_)
{
    struct ip_proto_info const *info = DOWNCAST(info_, info, ip_proto_info);
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "%s, version=%u, addr=%s->%s%s, proto=%u, ttl=%u",
        proto_info_2_str(info_),
        info->version,
        ip_addr_2_str(info->key.addr+0),
        ip_addr_2_str(info->key.addr+1),
        info->way ? " (hashed the other way)":"",
        info->key.protocol,
        info->ttl);
    return str;
}

static void ip_proto_info_ctor(struct ip_proto_info *info, struct parser *parser, struct proto_info const *parent, size_t head_len, size_t payload, struct ip_hdr const *iphdr)
{
    proto_info_ctor(&info->info, parser, parent, head_len, payload);

    info->version = iphdr->version;
    ip_addr_ctor_from_ip4(&info->key.addr[0], iphdr->src);
    ip_addr_ctor_from_ip4(&info->key.addr[1], iphdr->dst);
    info->key.protocol = iphdr->protocol;
    info->ttl = iphdr->ttl;
    info->way = 0;  // will be set later
}

/*
 * Subproto management
 */

static LIST_HEAD(ip_subprotos, ip_subproto) ip_subprotos;

void ip_subproto_ctor(struct ip_subproto *ip_subproto, unsigned protocol, struct proto *proto)
{
    SLOG(LOG_DEBUG, "Adding proto %s for protocol value %u", proto->name, protocol);
    ip_subproto->protocol = protocol;
    ip_subproto->proto = proto;
    LIST_INSERT_HEAD(&ip_subprotos, ip_subproto, entry);
}

void ip_subproto_dtor(struct ip_subproto *ip_subproto)
{
    SLOG(LOG_DEBUG, "Removing proto %s for protocol value %u", ip_subproto->proto->name, ip_subproto->protocol);
    LIST_REMOVE(ip_subproto, entry);
}

/*
 * Parse
 */

unsigned ip_key_ctor(struct ip_key *k, unsigned protocol, struct ip_addr const *src, struct ip_addr const *dst)
{
    k->protocol = protocol;
    if (ip_addr_cmp(src, dst) <= 0) {
        k->addr[0] = *src;
        k->addr[1] = *dst;
        return 0;
    }
    k->addr[0] = *dst;
    k->addr[1] = *src;
    return 1;
}

struct mux_subparser *ip_subparser_lookup(struct parser *parser, struct proto *proto, struct parser *requestor, unsigned protocol, struct ip_addr const *src, struct ip_addr const *dst, unsigned *way, struct timeval const *now)
{
    struct mux_parser *mux_parser = DOWNCAST(parser, parser, mux_parser);
    struct ip_key key;
    *way = ip_key_ctor(&key, protocol, src, dst);
    return mux_subparser_lookup(mux_parser, proto, requestor, &key, now);
}

static enum proto_parse_status ip_parse(struct parser *parser, struct proto_info const *parent, unsigned unused_ way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn)
{
    struct mux_parser *mux_parser = DOWNCAST(parser, parser, mux_parser);
    struct ip_hdr const *iphdr = (struct ip_hdr *)packet;

    // Sanity checks

    if (cap_len < sizeof(*iphdr)) return PROTO_TOO_SHORT;

    SLOG(LOG_DEBUG, "New packet of %zu bytes, proto %hu, %"PRINIPQUAD"->%"PRINIPQUAD,
        wire_len, iphdr->protocol, NIPQUAD(&iphdr->src), NIPQUAD(&iphdr->dst));

    size_t ip_len = ntohs(iphdr->tot_len);
    if (ip_len > wire_len) {
        SLOG(LOG_DEBUG, "Bogus IPv4 total length : %zu > %zu", ip_len, wire_len);
        return PROTO_PARSE_ERR;
    }

    if (iphdr->version != 4) {
        SLOG(LOG_DEBUG, "Bogus IPv4 version : %u instead of 4", (unsigned)iphdr->version);
        return PROTO_PARSE_ERR;
    }

    size_t iphdr_len = iphdr->hdr_len * 4;
    if (iphdr_len > ip_len) {
        SLOG(LOG_DEBUG, "Bogus IPv4 header length : %zu > %zu", iphdr_len, ip_len);
        return PROTO_PARSE_ERR;
    }

    if (iphdr_len > cap_len) return PROTO_TOO_SHORT;

    // Parse

    struct ip_proto_info info;
    ip_proto_info_ctor(&info, parser, parent, iphdr_len, ip_len - iphdr_len, iphdr);

    // Parse payload

    struct mux_subparser *subparser = NULL;
    struct ip_subproto *subproto;
    LIST_FOREACH(subproto, &ip_subprotos, entry) {
        if (subproto->protocol == info.key.protocol) {
            struct ip_key subparser_key;
            info.way = ip_key_ctor(&subparser_key, info.key.protocol, info.key.addr+0, info.key.addr+1);
            subparser = mux_subparser_lookup(mux_parser, subproto->proto, NULL, &subparser_key, now);
            break;
        }
    }
    if (! subparser) {
        SLOG(LOG_DEBUG, "IPv4 protocol %u unknown", iphdr->protocol);
        goto fallback;
    }

    if (0 != proto_parse(subparser->parser, &info.info, info.way, packet + iphdr_len, cap_len - iphdr_len, wire_len - iphdr_len, now, okfn)) goto fallback;
    return PROTO_OK;

fallback:
    (void)proto_parse(NULL, &info.info, info.way, packet + iphdr_len, cap_len - iphdr_len, wire_len - iphdr_len, now, okfn);
    return PROTO_OK;
}

/*
 * Construction/Destruction
 */

static struct mux_proto mux_proto_ip;
struct proto *proto_ip = &mux_proto_ip.proto;
static struct eth_subproto eth_subproto;

void ip_init(void)
{
    log_category_proto_ip_init();

    static struct proto_ops const ops = {
        .parse = ip_parse,
        .parser_new = mux_parser_new,
        .parser_del = mux_parser_del,
        .info_2_str = ip_info_2_str,
    };
    mux_proto_ctor(&mux_proto_ip, &ops, &mux_proto_ops, "IPv4", IP_TIMEOUT, sizeof(struct ip_key), IP_HASH_SIZE);
    eth_subproto_ctor(&eth_subproto, ETH_PROTO_IPv4, proto_ip);
    LIST_INIT(&ip_subprotos);
}

void ip_fini(void)
{
    assert(LIST_EMPTY(&ip_subprotos));
    eth_subproto_dtor(&eth_subproto);
    mux_proto_dtor(&mux_proto_ip);
    log_category_proto_ip_fini();
}
