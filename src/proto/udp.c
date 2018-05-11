// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2018, SecurActive.
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
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>
#include <inttypes.h>
#include "junkie/cpp.h"
#include "junkie/tools/ext.h"
#include "junkie/tools/tempstr.h"
#include "junkie/tools/log.h"
#include "junkie/proto/cnxtrack.h"
#include "junkie/proto/ip.h"
#include "junkie/proto/udp.h"
#include "proto/ip_hdr.h"

#undef LOG_CAT
#define LOG_CAT proto_udp_log_category

LOG_CATEGORY_DEF(proto_udp);

#define UDP_HASH_SIZE 67

/*
 * Proto Infos
 */

static void const *udp_info_addr(struct proto_info const *info_, size_t *size)
{
    struct udp_proto_info const *info = DOWNCAST(info_, info, udp_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *udp_info_2_str(struct proto_info const *info_)
{
    struct udp_proto_info const *info = DOWNCAST(info_, info, udp_proto_info);
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "%s, ports=%"PRIu16"->%"PRIu16,
        proto_info_2_str(info_),
        info->key.port[0], info->key.port[1]);
    return str;
}

static void udp_proto_info_ctor(struct udp_proto_info *info, struct parser *parser, struct proto_info *parent, size_t head_len, size_t payload, uint16_t sport, uint16_t dport)
{
    proto_info_ctor(&info->info, parser, parent, head_len, payload);

    info->key.port[0] = sport;
    info->key.port[1] = dport;
}

/*
 * Subproto management
 */

struct port_muxer_list udp_port_muxers;

static struct ext_function sg_udp_ports;
static SCM g_udp_ports(void)
{
    return g_port_muxer_list(&udp_port_muxers);
}

static struct ext_function sg_udp_add_port;
static SCM g_udp_add_port(SCM name, SCM port_min, SCM port_max)
{
    return g_port_muxer_add(&udp_port_muxers, name, port_min, port_max);
}

static struct ext_function sg_udp_del_port;
static SCM g_udp_del_port(SCM name, SCM port_min, SCM port_max)
{
    return g_port_muxer_del(&udp_port_muxers, name, port_min, port_max);
}

/*
 * Parse
 */

struct mux_subparser *udp_subparser_and_parser_new(struct parser *parser, struct proto *proto, struct proto *requestor, uint16_t src, uint16_t dst, unsigned way, struct timeval const *now)
{
    assert(parser->proto == proto_udp);
    struct mux_parser *mux_parser = DOWNCAST(parser, parser, mux_parser);
    struct port_key key;
    port_key_init(&key, src, dst, way);
    return mux_subparser_and_parser_new(mux_parser, proto, requestor, &key, now);
}

struct mux_subparser *udp_subparser_lookup(struct parser *parser, struct proto *proto, struct proto *requestor, uint16_t src, uint16_t dst, unsigned way, struct timeval const *now)
{
    assert(parser->proto == proto_udp);
    struct mux_parser *mux_parser = DOWNCAST(parser, parser, mux_parser);
    struct port_key key;
    port_key_init(&key, src, dst, way);
    return mux_subparser_lookup(mux_parser, proto, requestor, &key, now);
}

enum proto_parse_status udp_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct mux_parser *mux_parser = DOWNCAST(parser, parser, mux_parser);
    struct udp_hdr const *udphdr = (struct udp_hdr *)packet;

    // Sanity checks
    if (wire_len < sizeof(*udphdr)) {
        SLOG(LOG_DEBUG, "Bogus UDP packet: too short (%zu < %zu)", wire_len, sizeof(*udphdr));
        return PROTO_PARSE_ERR;
    }

    if (cap_len < sizeof(*udphdr)) return PROTO_TOO_SHORT;

    size_t tot_len = READ_U16N(&udphdr->len);
    if (tot_len < sizeof(*udphdr)) {
        SLOG(LOG_DEBUG, "Bogus UDP packet: UDP tot len shorter than UDP header (%zu < %zu)", tot_len, sizeof(*udphdr));
        return PROTO_PARSE_ERR;
    }

    size_t payload = tot_len - sizeof(*udphdr);
    if (payload > wire_len) {
        SLOG(LOG_DEBUG, "Bogus UDP packet: wrong length %zu > %zu", payload, wire_len);
        return PROTO_PARSE_ERR;
    }

    uint16_t const sport = READ_U16N(&udphdr->src);
    uint16_t const dport = READ_U16N(&udphdr->dst);
    SLOG(LOG_DEBUG, "New UDP packet of %zu bytes (%zu captured), ports %"PRIu16" -> %"PRIu16, wire_len, cap_len, sport, dport);

    // Parse

    struct udp_proto_info info;
    udp_proto_info_ctor(&info, parser, parent, sizeof(*udphdr), payload, sport, dport);

    // Search an already spawned subparser
    struct port_key key;
    port_key_init(&key, sport, dport, way);
    struct mux_subparser *subparser = mux_subparser_lookup(mux_parser, NULL, NULL, &key, now);
    if (subparser) SLOG(LOG_DEBUG, "Found subparser for this cnx, for proto %s", subparser->parser->proto->name);

    if (! subparser) {
        struct proto *requestor = NULL;
        struct proto *sub_proto = NULL;
        // Use connection tracking first
        ASSIGN_INFO_OPT2(ip, ip6, parent);
        if (! ip) ip = ip6;
        if (ip) sub_proto = cnxtrack_ip_lookup(IPPROTO_UDP, ip->key.addr+0, sport, ip->key.addr+1, dport, now, &requestor);
        if (! sub_proto) { // Then try predefined ports first
            sub_proto = port_muxer_find(&udp_port_muxers, info.key.port[0], info.key.port[1]);
        }
        if (sub_proto) subparser = mux_subparser_and_parser_new(mux_parser, sub_proto, requestor, &key, now);
    }

    if (! subparser) goto fallback;

    enum proto_parse_status status = proto_parse(subparser->parser, &info.info, way, packet + sizeof(*udphdr), cap_len - sizeof(*udphdr), wire_len - sizeof(*udphdr), now, tot_cap_len, tot_packet);
    if (status == PROTO_PARSE_ERR) {
        SLOG(LOG_DEBUG, "No suitable subparser for this payload");
        mux_subparser_deindex(subparser);
    }
    mux_subparser_unref(&subparser);
    if (status == PROTO_OK) return PROTO_OK;

fallback:
    (void)proto_parse(NULL, &info.info, way, packet + sizeof(*udphdr), cap_len - sizeof(*udphdr), wire_len - sizeof(*udphdr), now, tot_cap_len, tot_packet);
    return PROTO_OK;
}

/*
 * Construction/Destruction
 */

static struct mux_proto mux_proto_udp;
struct proto *proto_udp = &mux_proto_udp.proto;
static struct ip_subproto ip_subproto, ip6_subproto;

void udp_init(void)
{
    log_category_proto_udp_init();

    static struct proto_ops const ops = {
        .parse       = udp_parse,
        .parser_new  = mux_parser_new,
        .parser_del  = mux_parser_del,
        .info_2_str  = udp_info_2_str,
        .info_addr   = udp_info_addr
    };
    mux_proto_ctor(&mux_proto_udp, &ops, &mux_proto_ops, "UDP", PROTO_CODE_UDP, sizeof(struct port_key), UDP_HASH_SIZE);
    port_muxer_list_ctor(&udp_port_muxers, "UDP muxers");

    ip_subproto_ctor(&ip_subproto, IPPROTO_UDP, proto_udp);
    ip6_subproto_ctor(&ip6_subproto, IPPROTO_UDP, proto_udp);

    // Extension functions to introspect (and modify) port_muxers
    ext_function_ctor(&sg_udp_ports,
        "udp-ports", 0, 0, 0, g_udp_ports,
        "(udp-ports): returns an assoc-list of all defined udp subparsers with their port binding.\n");

    ext_function_ctor(&sg_udp_add_port,
        "udp-add-port", 2, 1, 0, g_udp_add_port,
        "(udp-add-port \"proto\" port [port-max]): ask TCP to try this proto for this port [range].\n"
        "See also (? 'udp-del-port)\n");

    ext_function_ctor(&sg_udp_del_port,
        "udp-del-port", 2, 1, 0, g_udp_del_port,
        "(udp-del-port \"proto\" port [port-max]): ask TCP to stop trying this proto for this port [range].\n"
        "See also (? 'udp-add-port)");
}

void udp_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    port_muxer_list_dtor(&udp_port_muxers);
    ip_subproto_dtor(&ip_subproto);
    ip6_subproto_dtor(&ip6_subproto);
    mux_proto_dtor(&mux_proto_udp);
#   endif

    log_category_proto_udp_fini();
}
