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
#include "junkie/cpp.h"
#include "junkie/tools/ext.h"
#include "junkie/tools/objalloc.h"
#include "junkie/tools/hash.h"
#include "junkie/tools/tempstr.h"
#include "junkie/tools/log.h"
#include "junkie/tools/queue.h"
#include "junkie/proto/cnxtrack.h"
#include "junkie/proto/pkt_wait_list.h"
#include "junkie/proto/ip.h"
#include "junkie/proto/tcp.h"
#include "proto/ip_hdr.h"

#undef LOG_CAT
#define LOG_CAT proto_tcp_log_category

LOG_CATEGORY_DEF(proto_tcp);

#define TCP_HASH_SIZE 67

/*
 * Proto Infos
 */

static void const *tcp_info_addr(struct proto_info const *info_, size_t *size)
{
    struct tcp_proto_info const *info = DOWNCAST(info_, info, tcp_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *tcp_options_2_str(struct tcp_proto_info const *info)
{
    char *tmp = tempstr();
    char *t = tmp;
    for (unsigned o = 0; o < info->nb_options; o++) {
        switch (info->options[o]) {
            case 0:  t += snprintf(t, TEMPSTR_SIZE - (t-tmp), ",end"); break;
            case 1:  t += snprintf(t, TEMPSTR_SIZE - (t-tmp), ",nop"); break;
            case 2:  t += snprintf(t, TEMPSTR_SIZE - (t-tmp), ",MSS(%"PRIu16")", info->mss); break;
            case 3:  t += snprintf(t, TEMPSTR_SIZE - (t-tmp), ",WSF(%"PRIu8")", info->wsf); break;
            default: t += snprintf(t, TEMPSTR_SIZE - (t-tmp), ",%"PRIu8, info->options[o]); break;
        }
    }
    return t > tmp ? tmp+1 : "none";    // skip the initial ','
}

static char const *tcp_info_2_str(struct proto_info const *info_)
{
    struct tcp_proto_info const *info = DOWNCAST(info_, info, tcp_proto_info);
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "%s, ports=%"PRIu16"%s->%"PRIu16"%s, flags=%s%s%s%s%s%s, win=%"PRIu16", ack=%"PRIu32", seq=%"PRIu32" (%"PRIu32"), urg=%"PRIx16", opts=%s",
        proto_info_2_str(info_),
        info->key.port[0], info->to_srv ? "":"(srv)",
        info->key.port[1], info->to_srv ? "(srv)":"",
        info->syn ? "Syn":"",
        info->ack ? "Ack":"",
        info->rst ? "Rst":"",
        info->fin ? "Fin":"",
        info->urg ? "Urg":"",
        info->psh ? "Psh":"",
        info->window,
        info->ack_num,
        info->seq_num,
        info->rel_seq_num,
        info->urg_ptr,
        tcp_options_2_str(info));
    return str;
}

static void tcp_proto_info_ctor(struct tcp_proto_info *info, struct parser *parser, struct proto_info *parent, size_t head_len, size_t payload, uint16_t sport, uint16_t dport, struct tcp_hdr const *tcphdr)
{
    proto_info_ctor(&info->info, parser, parent, head_len, payload);

    info->key.port[0] = sport;
    info->key.port[1] = dport;
    uint8_t const flags = READ_U8(&tcphdr->flags);
    info->syn = !!(flags & TCP_SYN_MASK);
    info->ack = !!(flags & TCP_ACK_MASK);
    info->rst = !!(flags & TCP_RST_MASK);
    info->fin = !!(flags & TCP_FIN_MASK);
    info->urg = !!(flags & TCP_URG_MASK);
    info->psh = !!(flags & TCP_PSH_MASK);
    // to_srv set later from tcp_subparser
    info->window = READ_U16N(&tcphdr->window);
    info->urg_ptr = READ_U16N(&tcphdr->urg_ptr);
    info->ack_num = READ_U32N(&tcphdr->ack_seq);
    info->seq_num = READ_U32N(&tcphdr->seq_num);
    info->rel_seq_num = 0U;
    info->set_values = 0;   // options will be set later
    info->nb_options = 0;
}

static ssize_t parse_next_option(struct tcp_proto_info *info, uint8_t const *options, size_t rem_len)
{
    assert(rem_len > 0);
    if (rem_len < 1) return -1;

    uint8_t const kind = options[0];

    // We only decode MSS and WSF but record all options
    if (info->nb_options < NB_ELEMS(info->options)) {
        info->options[info->nb_options++] = kind;
    }

    if (kind == 0) {    // end of option list
        if (rem_len > 4) {
            SLOG(LOG_DEBUG, "Option list terminated while %zu bytes left", rem_len-1);
            return rem_len; // keep parsing payload
        }
        if ((intptr_t)(options+rem_len) & 0x3) {
            SLOG(LOG_DEBUG, "Option list ends in a non word boundary");
            return -1;
        }
        // TODO: check that padding is composed of zeros
        return rem_len;
    } else if (kind == 1) {
        return 1;
    }

    if (rem_len < 2) {
        SLOG(LOG_DEBUG, "Invalid TCP options: can't read length");
        return -1;
    }
    size_t const len = options[1];  // len includes what's read before
    if (len < 2) {
        SLOG(LOG_DEBUG, "Invalid TCP options: len field (%zu) < 2", len);
        return -1;
    }
    if (rem_len < len) {
        SLOG(LOG_DEBUG, "Invalid TCP options: length (%zu) > rem options bytes (%zu)", len, rem_len);
        return -1;
    }

    switch (kind) {
        case 2: // MSS
            if (len != 4) {
                SLOG(LOG_DEBUG, "MSS with length %zu", len);
                return -1;
            }
            info->set_values |= TCP_MSS_SET;
            info->mss = READ_U16N(options+2);
            break;
        case 3: // Window Scale Factor
            if (len != 3) {
                SLOG(LOG_DEBUG, "WSF with length %zu", len);
                return -1;
            }
            info->set_values |= TCP_WSF_SET;
            info->wsf = options[2];
            break;
    }

    return len;
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

static struct pkt_wl_config tcp_wl_config;

static struct mutex_pool tcp_locks;

// We overload the mux_subparser in order to store a waiting list.
struct tcp_subparser {
    uint32_t fin_seqnum[2];     // indice = way
    uint32_t max_acknum[2];
    uint32_t isn[2];            // if syn, used to compute relative seqnum.
    uint32_t wl_origin[2];      // if origin, the origin for our waiting list (ideally, wl_origin == isn).
    struct pkt_wait_list wl[2]; // for packets reordering. offsets will be relative to wl_origin
    struct mutex *mutex;        // protects this structure
#   define SET_FOR_WAY(way, field) (field |= (1U<<way))
#   define RESET_FOR_WAY(way, field) (field &= ~(1U<<way))
#   define IS_SET_FOR_WAY(way, field) (!!(field & (1U<<way)))
    uint8_t fin:2, ack:2, syn:2;
    uint8_t origin:2;           // do we have wl_origin set yet?
    uint8_t srv_way:1;          // is srv the peer[0] when way==0 or peer[0] when way==1 ? (UNSET if !srv_set)
    uint8_t srv_set:2;          // 0 -> UNSET, 1 -> UNSURE, 2 -> CERTAIN (and 3 -> BUG)
    struct mux_subparser mux_subparser; // must be the last member of this struct since mux_subparser is variable in size
};

int tcp_seqnum_cmp(uint32_t sa, uint32_t sb)
{
    uint32_t diff = sa - sb;
    if (0 == diff) return 0;
    else if (diff < 0x80000000U) return 1;
    else return -1;
}

// Tells if a seqnum is after another
static bool seqnum_gt(uint32_t sa, uint32_t sb)
{
    return tcp_seqnum_cmp(sa, sb) > 0;
}

// caller must own tcp_sub->mux_subparser.ref.mutex (ouf)
static bool tcp_subparser_term(struct tcp_subparser const *tcp_sub)
{
    return
        (IS_SET_FOR_WAY(0, tcp_sub->fin) && IS_SET_FOR_WAY(1, tcp_sub->ack) && seqnum_gt(tcp_sub->max_acknum[1], tcp_sub->fin_seqnum[0])) &&
        (IS_SET_FOR_WAY(1, tcp_sub->fin) && IS_SET_FOR_WAY(0, tcp_sub->ack) && seqnum_gt(tcp_sub->max_acknum[0], tcp_sub->fin_seqnum[1]));
}

static int tcp_subparser_ctor(struct tcp_subparser *tcp_sub, struct mux_parser *mux_parser, struct parser *child, struct proto *requestor, struct port_key const *key, struct timeval const *now)
{
    SLOG(LOG_DEBUG, "Constructing TCP subparser @%p", tcp_sub);

    CHECK_LAST_FIELD(tcp_subparser, mux_subparser, struct mux_subparser);

    tcp_sub->fin = 0;
    tcp_sub->ack = 0;
    tcp_sub->syn = 0;
    tcp_sub->origin = 0;
    tcp_sub->srv_set = 0;   // will be set later

    if (0 != pkt_wait_list_ctor(tcp_sub->wl+0, 0 /* relative to the ISN */, &tcp_wl_config, child, tcp_sub->wl+1)) {
        return -1;
    }

    if (0 != pkt_wait_list_ctor(tcp_sub->wl+1, 0 /* relative to the ISN */, &tcp_wl_config, child, tcp_sub->wl+0)) {
        pkt_wait_list_dtor(tcp_sub->wl+0);
        return -1;
    }

    tcp_sub->mutex = mutex_pool_anyone(&tcp_locks);

    // Now that everything is ready, make this subparser public
    if (0 != mux_subparser_ctor(&tcp_sub->mux_subparser, mux_parser, child, requestor, key, now)) {
        pkt_wait_list_dtor(tcp_sub->wl+0);
        pkt_wait_list_dtor(tcp_sub->wl+1);
        return -1;
    }

    return 0;
}

static struct mux_subparser *tcp_subparser_new(struct mux_parser *mux_parser, struct parser *child, struct proto *requestor, void const *key, struct timeval const *now)
{
    struct tcp_subparser *tcp_subparser = mux_subparser_alloc(mux_parser, sizeof(*tcp_subparser));
    if (! tcp_subparser) return NULL;

    if (0 != tcp_subparser_ctor(tcp_subparser, mux_parser, child, requestor, key, now)) {
        objfree(tcp_subparser);
        return NULL;
    }

    return &tcp_subparser->mux_subparser;
}

struct mux_subparser *tcp_subparser_and_parser_new(struct parser *parser, struct proto *proto, struct proto *requestor, uint16_t src, uint16_t dst, unsigned way, struct timeval const *now)
{
    assert(parser->proto == proto_tcp);
    struct mux_parser *mux_parser = DOWNCAST(parser, parser, mux_parser);
    struct port_key key;
    port_key_init(&key, src, dst, way);
    return mux_subparser_and_parser_new(mux_parser, proto, requestor, &key, now);
}

static void tcp_subparser_dtor(struct tcp_subparser *tcp_subparser)
{
    SLOG(LOG_DEBUG, "Destructing TCP subparser @%p", tcp_subparser);

    pkt_wait_list_dtor(tcp_subparser->wl+0);
    pkt_wait_list_dtor(tcp_subparser->wl+1);

    mux_subparser_dtor(&tcp_subparser->mux_subparser);
}

static void tcp_subparser_del(struct mux_subparser *mux_subparser)
{
    struct tcp_subparser *tcp_subparser = DOWNCAST(mux_subparser, mux_subparser, tcp_subparser);
    tcp_subparser_dtor(tcp_subparser);
    objfree(tcp_subparser);
}

struct mux_subparser *tcp_subparser_lookup(struct parser *parser, struct proto *proto, struct proto *requestor, uint16_t src, uint16_t dst, unsigned way, struct timeval const *now)
{
    assert(parser->proto == proto_tcp);
    struct mux_parser *mux_parser = DOWNCAST(parser, parser, mux_parser);
    struct port_key key;
    port_key_init(&key, src, dst, way);
    return mux_subparser_lookup(mux_parser, proto, requestor, &key, now);
}

static enum proto_parse_status tcp_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct mux_parser *mux_parser = DOWNCAST(parser, parser, mux_parser);
    struct tcp_hdr const *tcphdr = (struct tcp_hdr *)packet;

    // Sanity checks
    if (wire_len < sizeof(*tcphdr)) {
        SLOG(LOG_DEBUG, "Bogus TCP packet: too short (%zu < %zu)", wire_len, sizeof(*tcphdr));
        return PROTO_PARSE_ERR;
    }

    if (cap_len < sizeof(*tcphdr)) return PROTO_TOO_SHORT;

    size_t tcphdr_len = TCP_HDR_LENGTH(tcphdr);

    if (tcphdr_len < sizeof(*tcphdr)) {
        SLOG(LOG_DEBUG, "Bogus TCP packet: header size too smal (%zu < %zu)", tcphdr_len, sizeof(*tcphdr));
        return PROTO_PARSE_ERR;
    }

    if (tcphdr_len > wire_len) {
        SLOG(LOG_DEBUG, "Bogus TCP packet: wrong length %zu > %zu", tcphdr_len, wire_len);
        return PROTO_PARSE_ERR;
    }

    if (tcphdr_len > cap_len) return PROTO_TOO_SHORT;

    // TODO: move this below call to tcp_proto_info_ctor() and use info instead of reading tcphdr directly
    uint16_t const sport = READ_U16N(&tcphdr->src);
    uint16_t const dport = READ_U16N(&tcphdr->dst);
    bool const syn = !!(READ_U8(&tcphdr->flags) & TCP_SYN_MASK);
    bool const fin = !!(READ_U8(&tcphdr->flags) & TCP_FIN_MASK);
    bool const ack = !!(READ_U8(&tcphdr->flags) & TCP_ACK_MASK);
    bool const rst = !!(READ_U8(&tcphdr->flags) & TCP_RST_MASK);
    bool const urg = !!(READ_U8(&tcphdr->flags) & TCP_URG_MASK);
    bool const psh = !!(READ_U8(&tcphdr->flags) & TCP_PSH_MASK);
    SLOG(LOG_DEBUG, "New TCP packet of %zu bytes (%zu captured), %zu payload, ports %"PRIu16" -> %"PRIu16" Flags: %s%s%s%s%s%s, Seq:%"PRIu32", Ack:%"PRIu32,
        wire_len, cap_len, wire_len - tcphdr_len, sport, dport,
        syn ? "Syn":"", fin ? "Fin":"", ack ? "Ack":"", rst ? "Rst":"", urg ? "Urg":"", psh ? "Psh":"",
        READ_U32N(&tcphdr->seq_num), READ_U32N(&tcphdr->ack_seq));

    // Parse

    struct tcp_proto_info info;
    tcp_proto_info_ctor(&info, parser, parent, tcphdr_len, wire_len - tcphdr_len, sport, dport, tcphdr);

    // Parse TCP options
    uint8_t const *options = (uint8_t *)(tcphdr+1);
    assert(tcphdr_len >= sizeof(*tcphdr));
    for (size_t rem_len = tcphdr_len - sizeof(*tcphdr); rem_len > 0; ) {
        ssize_t const len = parse_next_option(&info, options, rem_len);
        if (len < 0) return PROTO_PARSE_ERR;
        rem_len -= len;
        options += len;
    }

    // Search an already spawned subparser
    struct port_key key;
    port_key_init(&key, sport, dport, way);
    struct mux_subparser *subparser = mux_subparser_lookup(mux_parser, NULL, NULL, &key, now);
    if (subparser) SLOG(LOG_DEBUG, "Found subparser@%p for this cnx, for proto %s", subparser->parser, subparser->parser->proto->name);

    if (! subparser) {
        struct proto *requestor = NULL;
        struct proto *sub_proto = NULL;
        // Use connection tracking first
        ASSIGN_INFO_OPT2(ip, ip6, parent);
        if (! ip) ip = ip6;
        if (ip) sub_proto = cnxtrack_ip_lookup(IPPROTO_TCP, ip->key.addr+0, sport, ip->key.addr+1, dport, now, &requestor);
        if (! sub_proto) { // Then try predefined ports
            sub_proto = port_muxer_find(&tcp_port_muxers, info.key.port[0], info.key.port[1]);
        }
        if (sub_proto) {
            subparser = mux_subparser_and_parser_new(mux_parser, sub_proto, requestor, &key, now);
        } else {
            // Even if we have no child parser to send payload to, we want to submit payload in stream order to our plugins
            subparser = tcp_subparser_new(mux_parser, NULL, NULL, &key, now);
        }
    }

    if (! subparser) goto fallback;

    // Keep track of TCP flags & ISN
    struct tcp_subparser *tcp_sub = DOWNCAST(subparser, mux_subparser, tcp_subparser);
    mutex_lock(tcp_sub->mutex);
    if (
        info.ack &&
        (!IS_SET_FOR_WAY(way, tcp_sub->ack) || seqnum_gt(info.ack_num, tcp_sub->max_acknum[way]))
    ) {
        SET_FOR_WAY(way, tcp_sub->ack);
        tcp_sub->max_acknum[way] = info.ack_num;
    }
    if (info.fin) {
        SET_FOR_WAY(way, tcp_sub->fin);
        tcp_sub->fin_seqnum[way] = info.seq_num + info.info.payload;    // The FIN is acked after the payload
    }
    if (info.syn && !IS_SET_FOR_WAY(way, tcp_sub->syn)) {
        SET_FOR_WAY(way, tcp_sub->syn);
        tcp_sub->isn[way] = info.seq_num;
    }
    if (!IS_SET_FOR_WAY(way, tcp_sub->origin)) {
        SET_FOR_WAY(way, tcp_sub->origin);
        tcp_sub->wl_origin[way] = info.seq_num;
        if (! IS_SET_FOR_WAY(way, tcp_sub->syn)) SLOG(LOG_DEBUG, "Starting a WL while SYN is yet to be received!");
    }

    // Set relative sequence number if we know it
    if (IS_SET_FOR_WAY(way, tcp_sub->syn)) info.rel_seq_num = info.seq_num - tcp_sub->isn[way];

    // Set srv_way
    assert(tcp_sub->srv_set < 3);
    if (tcp_sub->srv_set == 0 || (tcp_sub->srv_set == 1 && info.syn)) {
        if (comes_from_client(info.key.port, info.syn, info.ack)) {
            // this packet comes from the client
            tcp_sub->srv_way = !way;
        } else {
            tcp_sub->srv_way = way;
        }
        tcp_sub->srv_set = info.syn ? 2:1;
    }
    // Now patch it into tcp info
    info.to_srv = tcp_sub->srv_way != way;

    SLOG(LOG_DEBUG, "Subparser@%p state: >ISN:%"PRIu32"%s Fin:%"PRIu32" Ack:%"PRIu32" <ISN:%"PRIu32"%s Fin:%"PRIu32" Ack:%"PRIu32", SrvWay=%u%s",
        subparser->parser,
        IS_SET_FOR_WAY(0, tcp_sub->syn) ? tcp_sub->isn[0] : IS_SET_FOR_WAY(0, tcp_sub->origin) ? tcp_sub->wl_origin[0] : 0,
        IS_SET_FOR_WAY(0, tcp_sub->syn) ? "" : " (approx)",
        IS_SET_FOR_WAY(0, tcp_sub->fin) ? tcp_sub->fin_seqnum[0] : 0,
        IS_SET_FOR_WAY(0, tcp_sub->ack) ? tcp_sub->max_acknum[0] : 0,
        IS_SET_FOR_WAY(1, tcp_sub->syn) ? tcp_sub->isn[1] : IS_SET_FOR_WAY(1, tcp_sub->origin) ? tcp_sub->wl_origin[1] : 0,
        IS_SET_FOR_WAY(1, tcp_sub->syn) ? "" : " (approx)",
        IS_SET_FOR_WAY(1, tcp_sub->fin) ? tcp_sub->fin_seqnum[1] : 0,
        IS_SET_FOR_WAY(1, tcp_sub->ack) ? tcp_sub->max_acknum[1] : 0,
        tcp_sub->srv_way,
        tcp_sub->srv_set == 0 ? " (unset)":
            tcp_sub->srv_set == 1 ? " (unsure)":"(certain)");

    enum proto_parse_status err;
    /* Use the wait_list to parse this packet.
       Notice that we do queue empty packets because subparser (or subscriber) want to receive all packets in order, including empty ones. */

    size_t const packet_len = wire_len - tcphdr_len;
    assert(IS_SET_FOR_WAY(way, tcp_sub->origin));
    unsigned const offset = info.seq_num - tcp_sub->wl_origin[way];
    unsigned const next_offset = offset + packet_len + info.syn + info.fin;
    unsigned const sync_offset = info.ack_num - tcp_sub->wl_origin[!way];  // we must not parse this one before we parsed (or timeouted) this one from wl[!way]
    // FIXME: Here the parser is chosen before we actually parse anything. If later the parser fails we cannot try another one.
    //        Choice of parser should be delayed until we start actual parse.
    bool const do_sync = info.ack && IS_SET_FOR_WAY(!way, tcp_sub->origin);
    err = pkt_wait_list_add(tcp_sub->wl+way, offset, next_offset, do_sync, sync_offset, true, &info.info, way, packet + tcphdr_len, cap_len - tcphdr_len, packet_len, now, tot_cap_len, tot_packet);
    SLOG(LOG_DEBUG, "Waiting list returned %s", proto_parse_status_2_str(err));

    if (err == PROTO_OK) {
        // Try advancing each WL until we are stuck or met an error
        pkt_wait_list_try_both(tcp_sub->wl+!way, &err, now, false);
    }

    bool const term = tcp_subparser_term(tcp_sub);
    mutex_unlock(tcp_sub->mutex);

    if (term || err == PROTO_PARSE_ERR) {
        if (term) {
            SLOG(LOG_DEBUG, "TCP cnx terminated (was %s)", parser_name(subparser->parser));
        } else {
            SLOG(LOG_DEBUG, "No suitable subparser for this payload");
        }
        mux_subparser_deindex(subparser);
    }
    mux_subparser_unref(&subparser);

    if (err == PROTO_OK) return PROTO_OK;

fallback:
    (void)proto_parse(NULL, &info.info, way, packet + tcphdr_len, cap_len - tcphdr_len, wire_len - tcphdr_len, now, tot_cap_len, tot_packet);
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
    mutex_pool_ctor(&tcp_locks, "TCP subparsers");
    log_category_proto_tcp_init();
    pkt_wl_config_ctor(&tcp_wl_config, "TCP-reordering", 100000, 20, 100000, 3 /* REORDERING TIMEOUT (second) */, true);

    static struct proto_ops const ops = {
        .parse       = tcp_parse,
        .parser_new  = mux_parser_new,
        .parser_del  = mux_parser_del,
        .info_2_str  = tcp_info_2_str,
        .info_addr   = tcp_info_addr
    };
    static struct mux_proto_ops const mux_ops = {
        .subparser_new = tcp_subparser_new,
        .subparser_del = tcp_subparser_del,
    };
    mux_proto_ctor(&mux_proto_tcp, &ops, &mux_ops, "TCP", PROTO_CODE_TCP, sizeof(struct port_key), TCP_HASH_SIZE);
    port_muxer_list_ctor(&tcp_port_muxers, "TCP muxers");
    ip_subproto_ctor(&ip_subproto, IPPROTO_TCP, proto_tcp);
    ip6_subproto_ctor(&ip6_subproto, IPPROTO_TCP, proto_tcp);

    // Extension functions to introspect (and modify) port_muxers
    ext_function_ctor(&sg_tcp_ports,
        "tcp-ports", 0, 0, 0, g_tcp_ports,
        "(tcp-ports): returns an assoc-list of all defined tcp subparsers with their port binding.\n");

    ext_function_ctor(&sg_tcp_add_port,
        "tcp-add-port", 2, 1, 0, g_tcp_add_port,
        "(tcp-add-port \"proto\" port [port-max]): ask TCP to try this proto for this port [range].\n"
        "See also (? 'tcp-del-port)\n");

    ext_function_ctor(&sg_tcp_del_port,
        "tcp-del-port", 2, 1, 0, g_tcp_del_port,
        "(tcp-del-port \"proto\" port [port-max]): ask TCP to stop trying this proto for this port [range].\n"
        "See also (? 'tcp-add-port)");
}

void tcp_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    port_muxer_list_dtor(&tcp_port_muxers);
    ip_subproto_dtor(&ip_subproto);
    ip6_subproto_dtor(&ip6_subproto);
    mux_proto_dtor(&mux_proto_tcp);
    pkt_wl_config_dtor(&tcp_wl_config);
    mutex_pool_dtor(&tcp_locks);
#   endif

    log_category_proto_tcp_fini();
}
