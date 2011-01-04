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
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <inttypes.h>
#include <stdio.h>
#include <junkie/cpp.h>
#include <junkie/ext.h>
#include <junkie/tools/mallocer.h>
#include <junkie/tools/hash.h>
#include <junkie/tools/tempstr.h>
#include <junkie/tools/log.h>
#include <junkie/tools/queue.h>
#include <junkie/proto/ip.h>
#include <junkie/proto/tcp.h>
#include "proto/ip_hdr.h"

static char const Id[] = "$Id: f1e4973c1763a7a217c77b2e7a667edf3f209eb7 $";

#undef LOG_CAT
#define LOG_CAT proto_tcp_log_category

LOG_CATEGORY_DEC(proto_tcp);
LOG_CATEGORY_DEF(proto_tcp);

#define TCP_TIMEOUT 120
#define TCP_HASH_SIZE 64

/*
 * Proto Infos
 */

static void const *tcp_info_addr(struct proto_info const *info_, size_t *size)
{
    struct tcp_proto_info const *info = DOWNCAST(info_, info, tcp_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *tcp_info_2_str(struct proto_info const *info_)
{
    struct tcp_proto_info const *info = DOWNCAST(info_, info, tcp_proto_info);
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "%s, ports=%"PRIu16"->%"PRIu16", flags=%s%s%s%s, win=%"PRIu16", ack=%"PRIu32", seq=%"PRIu32,
        proto_info_2_str(info_),
        info->key.port[0], info->key.port[1],
        info->syn ? "Syn":"",
        info->ack ? "Ack":"",
        info->rst ? "Rst":"",
        info->fin ? "Fin":"",
        info->window,
        info->ack_num,
        info->seq_num);
    return str;
}

static void tcp_proto_info_ctor(struct tcp_proto_info *info, struct parser *parser, struct proto_info *parent, size_t head_len, size_t payload, uint16_t sport, uint16_t dport, struct tcp_hdr const *tcphdr)
{
    proto_info_ctor(&info->info, parser, parent, head_len, payload);

    info->key.port[0] = sport;
    info->key.port[1] = dport;
    info->syn = tcphdr->syn;
    info->ack = tcphdr->ack;
    info->rst = tcphdr->rst;
    info->fin = tcphdr->fin;
    info->window = ntohs(tcphdr->window);
    info->ack_num = ntohl(tcphdr->ack_seq);
    info->seq_num = ntohl(tcphdr->seq_num);
}

/*
 * Subproto management
 */

struct port_muxer_list tcp_port_muxers;

static struct ext_function sg_tcp_ports;
static SCM g_tcp_ports(void)
{
    return g_port_muxer_list(&tcp_port_muxers);
}

static struct ext_function sg_tcp_add_port;
static SCM g_tcp_add_port(SCM name, SCM port_min, SCM port_max)
{
    return g_port_muxer_add(&tcp_port_muxers, name, port_min, port_max);
}

static struct ext_function sg_tcp_del_port;
static SCM g_tcp_del_port(SCM name, SCM port_min, SCM port_max)
{
    return g_port_muxer_del(&tcp_port_muxers, name, port_min, port_max);
}

/*
 * Parse
 */

// We overload the mux_subparser in order to store cnx state.
struct tcp_subparser {
    bool fin[2], ack[2];
    uint32_t fin_seqnum[2];    // indice = way
    uint32_t max_acknum[2];
    struct mux_subparser mux_subparser;
};

// Tells if a seqnum is after another
static bool seqnum_gt(uint32_t sa, uint32_t sb)
{
    uint32_t diff = sa - sb;
    return diff < 0x80000000U && diff != 0;
}

static bool tcp_subparser_term(struct tcp_subparser const *tcp_sub)
{
    return
        (tcp_sub->fin[0] && tcp_sub->ack[1] && seqnum_gt(tcp_sub->max_acknum[1], tcp_sub->fin_seqnum[0])) &&
        (tcp_sub->fin[1] && tcp_sub->ack[0] && seqnum_gt(tcp_sub->max_acknum[0], tcp_sub->fin_seqnum[1]));
}

static int tcp_subparser_ctor(struct tcp_subparser *tcp_subparser, struct mux_parser *mux_parser, struct parser *child, struct parser *requestor, void const *key)
{
    CHECK_LAST_FIELD(tcp_subparser, mux_subparser, struct mux_subparser);

    tcp_subparser->fin[0] = tcp_subparser->fin[1] = false;
    tcp_subparser->ack[0] = tcp_subparser->ack[1] = false;
    return mux_subparser_ctor(&tcp_subparser->mux_subparser, mux_parser, child, requestor, key);
}

static struct mux_subparser *tcp_subparser_new(struct mux_parser *mux_parser, struct parser *child, struct parser *requestor, void const *key)
{
    struct tcp_subparser *tcp_subparser = mux_subparser_alloc(mux_parser, sizeof(*tcp_subparser));
    if (! tcp_subparser) return NULL;

    if (0 != tcp_subparser_ctor(tcp_subparser, mux_parser, child, requestor, key)) {
        FREE(tcp_subparser);
        return NULL;
    }

    return &tcp_subparser->mux_subparser;
}

struct mux_subparser *tcp_subparser_and_parser_new(struct parser *parser, struct proto *proto, struct parser *requestor, uint16_t src, uint16_t dst, struct timeval const *now)
{
    assert(parser->proto == proto_tcp);
    struct mux_parser *mux_parser = DOWNCAST(parser, parser, mux_parser);

    struct tcp_key key = { .port = { src, dst } };
    return mux_subparser_and_parser_new(mux_parser, proto, requestor, &key, now);
}

static void tcp_subparser_del(struct mux_subparser *mux_subparser)
{
    struct tcp_subparser *tcp_subparser = DOWNCAST(mux_subparser, mux_subparser, tcp_subparser);
    mux_subparser_dtor(&tcp_subparser->mux_subparser);
    FREE(tcp_subparser);
}

static void tcp_key_init(struct tcp_key *key, uint16_t src, uint16_t dst, unsigned way)
{
    if (way == 0) {
        key->port[0] = src;
        key->port[1] = dst;
    } else {
        key->port[0] = dst;
        key->port[1] = src;
    }
}

struct mux_subparser *tcp_subparser_lookup(struct parser *parser, struct proto *proto, struct parser *requestor, uint16_t src, uint16_t dst, unsigned way, struct timeval const *now)
{
    assert(parser->proto == proto_tcp);
    struct mux_parser *mux_parser = DOWNCAST(parser, parser, mux_parser);
    struct tcp_key key;
    tcp_key_init(&key, src, dst, way);
    return mux_subparser_lookup(mux_parser, proto, requestor, &key, now);
}

static enum proto_parse_status tcp_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn)
{
    struct mux_parser *mux_parser = DOWNCAST(parser, parser, mux_parser);
    struct tcp_hdr const *tcphdr = (struct tcp_hdr *)packet;

    // Sanity checks
    if (wire_len < sizeof(*tcphdr)) {
        SLOG(LOG_DEBUG, "Bogus TCP packet : too short (%zu < %zu)", wire_len, sizeof(*tcphdr));
        return PROTO_PARSE_ERR;
    }

    if (cap_len < sizeof(*tcphdr)) return PROTO_TOO_SHORT;

    size_t tcphdr_len = tcphdr->doff * 4;
    if (tcphdr_len > wire_len) {
        SLOG(LOG_DEBUG, "Bogus TCP packet : wrong length %zu > %zu", tcphdr_len, wire_len);
        return -1;
    }

    if (tcphdr_len > cap_len) return PROTO_TOO_SHORT;

    uint16_t const sport = ntohs(tcphdr->src);
    uint16_t const dport = ntohs(tcphdr->dst);
    SLOG(LOG_DEBUG, "New TCP packet of %zu bytes (%zu captured), %zu payload, ports %"PRIu16" -> %"PRIu16" Flags: %s%s%s%s, Seq:%"PRIu32", Ack:%"PRIu32,
        wire_len, cap_len, wire_len - tcphdr_len, sport, dport,
        tcphdr->syn ? "Syn":"", tcphdr->fin ? "Fin":"", tcphdr->ack ? "Ack":"", tcphdr->rst ? "Rst":"",
        ntohl(tcphdr->seq_num), ntohl(tcphdr->ack_seq));

    // Parse

    struct tcp_proto_info info;
    tcp_proto_info_ctor(&info, parser, parent, tcphdr_len, wire_len - tcphdr_len, sport, dport, tcphdr);

    // Find out subparser based on exact ports
    struct tcp_key key;
    tcp_key_init(&key, sport, dport, way);
    struct mux_subparser *subparser = mux_subparser_lookup(mux_parser, NULL, NULL, &key, now);

    // Or using a wildcard port
    if (! subparser) {
        subparser = tcp_subparser_lookup(&mux_parser->parser, NULL, NULL, 0, dport, way, now);
        if (subparser) mux_subparser_change_key(subparser, mux_parser, &key);
    }
    if (! subparser) {
        subparser = tcp_subparser_lookup(&mux_parser->parser, NULL, NULL, sport, 0, way, now);
        if (subparser) mux_subparser_change_key(subparser, mux_parser, &key);
    }

    if (subparser) SLOG(LOG_DEBUG, "Found subparser for this cnx, for proto %s", subparser->parser->proto->name);

    // No one yet ? Then use port
    if (! subparser) {
        struct proto *sub_proto = port_muxer_find(&tcp_port_muxers, info.key.port[0]);
        if (! sub_proto) sub_proto = port_muxer_find(&tcp_port_muxers, info.key.port[1]);
        if (sub_proto) subparser = mux_subparser_and_parser_new(mux_parser, sub_proto, NULL, &key, now);
    }

    if (! subparser) goto fallback;

    // If the stream is over, we must delete the subparser before calling
    // proto_parse since we are not allowed to keep a ref on a subparser across
    // proto_parse (since proto_parse can lead to the creation of a new
    // subparser, which can trigger the deletion of another subparser at random
    // if nb_children hits max). So we ref the parser and kill the subparser
    // before calling proto_parse.
    // FIXME: we would like to be able to keep a ref on a subparser since we
    // could want to delete a subparser based on the returned value of
    // proto_parse !
    struct parser *child = parser_ref(subparser->parser);

    // Keep track of TCP flags
    struct tcp_subparser *tcp_sub = DOWNCAST(subparser, mux_subparser, tcp_subparser);
    if (
        info.ack &&
        (!tcp_sub->ack[way] || seqnum_gt(info.ack_num, tcp_sub->max_acknum[way]))
       ) {
        tcp_sub->ack[way] = true;
        tcp_sub->max_acknum[way] = info.ack_num;
    }
    if (info.fin) {
        tcp_sub->fin[way] = true;
        tcp_sub->fin_seqnum[way] = info.seq_num + info.info.payload;    // The FIN is acked after the payload
    }

    SLOG(LOG_DEBUG, "This subparser state : >Fin:%"PRIu32" Ack:%"PRIu32" <Fin:%"PRIu32" Ack:%"PRIu32,
        tcp_sub->fin[0] ? tcp_sub->fin_seqnum[0] : 0,
        tcp_sub->ack[0] ? tcp_sub->max_acknum[0] : 0,
        tcp_sub->fin[1] ? tcp_sub->fin_seqnum[1] : 0,
        tcp_sub->ack[1] ? tcp_sub->max_acknum[1] : 0);

    if (tcp_subparser_term(tcp_sub)) {
        SLOG(LOG_DEBUG, "TCP cnx terminated (was %s)", parser_name(subparser->parser));
        tcp_subparser_del(subparser);
    }

    int err = proto_parse(child, &info.info, way, packet + tcphdr_len, cap_len - tcphdr_len, wire_len - tcphdr_len, now, okfn);
    parser_unref(child);
    if (err) goto fallback;
    return PROTO_OK;

fallback:
    (void)proto_parse(NULL, &info.info, way, packet + tcphdr_len, cap_len - tcphdr_len, wire_len - tcphdr_len, now, okfn);
    return PROTO_OK;
}

/*
 * Init
 */

static struct mux_proto mux_proto_tcp;
struct proto *proto_tcp = &mux_proto_tcp.proto;
static struct ip_subproto ip_subproto, ip6_subproto;

void tcp_init(void)
{
    log_category_proto_tcp_init();

    static struct proto_ops const ops = {
        .parse      = tcp_parse,
        .parser_new = mux_parser_new,
        .parser_del = mux_parser_del,
        .info_2_str = tcp_info_2_str,
        .info_addr  = tcp_info_addr,
    };
    static struct mux_proto_ops const mux_ops = {
        .subparser_new = tcp_subparser_new,
        .subparser_del = tcp_subparser_del,
    };
    mux_proto_ctor(&mux_proto_tcp, &ops, &mux_ops, "TCP", TCP_TIMEOUT, sizeof(struct tcp_key), TCP_HASH_SIZE);
    port_muxer_list_ctor(&tcp_port_muxers, "TCP muxers");
    ip_subproto_ctor(&ip_subproto, IPPROTO_TCP, proto_tcp);
    ip6_subproto_ctor(&ip6_subproto, IPPROTO_TCP, proto_tcp);

    // Extension functions to introspect (and modify) port_muxers
    ext_function_ctor(&sg_tcp_ports,
        "tcp-ports", 0, 0, 0, g_tcp_ports,
        "(tcp-ports) : returns an assoc-list of all defined tcp subparsers with their port binding.\n");

    ext_function_ctor(&sg_tcp_add_port,
        "tcp-add-port", 2, 1, 0, g_tcp_add_port,
        "(tcp-add-port \"proto\" port [port-max]) : ask TCP to try this proto for this port [range].\n"
        "See also (? 'tcp-del-port)\n");

    ext_function_ctor(&sg_tcp_del_port,
        "tcp-del-port", 2, 1, 0, g_tcp_del_port,
        "(udp-del-port \"proto\" port [port-max]) : ask TCP to stop trying this proto for this port [range].\n"
        "See also (? 'tcp-add-port)");
}

void tcp_fini(void)
{
    port_muxer_list_dtor(&tcp_port_muxers);
    ip_subproto_dtor(&ip_subproto);
    ip6_subproto_dtor(&ip6_subproto);
    mux_proto_dtor(&mux_proto_tcp);
    log_category_proto_tcp_fini();
}
