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
#include "junkie/proto/serialize.h"

extern inline void serialize_1(uint8_t **buf, unsigned v);
extern inline void serialize_2(uint8_t **buf, unsigned v);
extern inline void serialize_3(uint8_t **buf, unsigned v);
extern inline void serialize_4(uint8_t **buf, unsigned v);
extern inline void serialize_n(uint8_t **buf, void const *src, size_t n);
extern inline void serialize_str(uint8_t **buf, char const *s);
extern inline unsigned deserialize_1(uint8_t const **buf);
extern inline uint16_t deserialize_2(uint8_t const **buf);
extern inline uint32_t deserialize_3(uint8_t const **buf);
extern inline uint32_t deserialize_4(uint8_t const **buf);
extern inline void deserialize_n(uint8_t const **buf, void *dst, size_t n);
extern inline void deserialize_str(uint8_t const **buf, char *dst, size_t max_len);

/*
 * Serialization
 */

static void serialize_info_rec(unsigned depth, uint8_t **buf, struct proto_info const *info)
{
    if (info->parent != NULL) {
        serialize_info_rec(depth+1, buf, info->parent);
    } else {
        serialize_1(buf, depth);    // The msg starts with the depth of the protocol stack (so that we can pack several info into a single msg)
    }
    ASSERT_COMPILE(PROTO_CODE_MAX <= 255);
    serialize_1(buf, info->parser->proto->code);    // each proto start with its code
    if (info->parser->proto->ops->serialize) {
        // Some protocols may not implement this
        info->parser->proto->ops->serialize(info, buf);
    }
}

void serialize_proto_stack(uint8_t **buf, struct proto_info const *last)
{
    serialize_info_rec(1, buf, last);
}

/*
 * Deserialization
 */

#include "junkie/proto/cap.h"
#include "junkie/proto/eth.h"
#include "junkie/proto/ip.h"
#include "junkie/proto/gre.h"
#include "junkie/proto/arp.h"
#include "junkie/proto/udp.h"
#include "junkie/proto/icmp.h"
#include "junkie/proto/tcp.h"
#include "junkie/proto/sip.h"
#include "junkie/proto/bittorrent.h"
#include "junkie/proto/http.h"
#include "junkie/proto/rtp.h"
#include "junkie/proto/netbios.h"
#include "junkie/proto/ssl.h"
#include "junkie/proto/dns.h"
#include "junkie/proto/rtcp.h"
#include "junkie/proto/ftp.h"
#include "junkie/proto/mgcp.h"
#include "junkie/proto/sdp.h"
#include "junkie/proto/sql.h"

static int deserialize_proto_info_rec(unsigned depth, uint8_t const **buf, struct proto_info *last, int (*okfn)(struct proto_info *))
{
    if (depth == 0) return okfn(last);

    enum proto_code code = deserialize_1(buf); // read the code
    if (code >= PROTO_CODE_MAX) {
        SLOG(LOG_WARNING, "Unknown protocol code %u", code);
        return okfn(last);
    }

    union {
        struct cap_proto_info cap;
        struct eth_proto_info eth;
        struct arp_proto_info arp;
        struct ip_proto_info ip;
        struct ip6_proto_info ip6;
        struct udp_proto_info udp;
        struct tcp_proto_info tcp;
        struct dns_proto_info dns;
        struct ftp_proto_info ftp;
        struct gre_proto_info gre;
        struct http_proto_info http;
        struct icmp_proto_info icmp;
        struct mgcp_proto_info mgcp;
        struct rtcp_proto_info rtcp;
        struct rtp_proto_info rtp;
        struct sdp_proto_info sdp;
        struct sip_proto_info sip;
        struct sql_proto_info tns;
        struct sql_proto_info postgres;
        struct sql_proto_info mysql;
        struct bittorrent_proto_info bittorrent;
        struct netbios_proto_info netbios;
        struct ssl_proto_info ssl;
    } i;
    struct proto_info *info = NULL;
    struct proto *proto = NULL;
    switch (code) {
#       define CASE(NAME, name) \
        case PROTO_CODE_##NAME: \
            info = &i.name.info; \
            proto = proto_##name; \
            break
        CASE(CAP, cap); CASE(ETH, eth); CASE(ARP, arp);
        CASE(IP, ip); CASE(IP6, ip6); CASE(UDP, udp);
        CASE(TCP, tcp); CASE(DNS, dns); CASE(FTP, ftp);
        CASE(GRE, gre); CASE(HTTP, http); CASE(ICMP, icmp);
        CASE(MGCP, mgcp); CASE(RTCP, rtcp); CASE(RTP, rtp);
        CASE(SDP, sdp); CASE(SIP, sip); CASE(TNS, tns);
        CASE(PGSQL, postgres); CASE(MYSQL, mysql); CASE(BITTORRENT, bittorrent);
        CASE(NETBIOS, netbios); CASE(SSL, ssl);
#       undef CASE
        case PROTO_CODE_DUMMY:
        case PROTO_CODE_MAX:
            break;
    }
    if (! info) {
        SLOG(LOG_WARNING, "Unknown proto code %u", code);
        return okfn(last);
    }

    assert(proto);
    if (proto->ops->deserialize) {
        proto->ops->deserialize(info, buf);
        info->parent = last;
        struct parser dummy_parser = { .proto = proto }; // A dummy parser just so that okfn can dereference proto
        info->parser = &dummy_parser;
    } else {
        if (proto->ops->serialize) {
            SLOG(LOG_WARNING, "No deserializer for proto %s", proto->name);
            return okfn(last);
        }
        info = last;    // skip this layer
    }

    return deserialize_proto_info_rec(depth-1, buf, info, okfn);
}

int deserialize_proto_stack(uint8_t const **buf, int (*okfn)(struct proto_info *))
{
    unsigned depth = deserialize_1(buf);   // the msg starts with the protocol stack depth
    int ret = deserialize_proto_info_rec(depth, buf, NULL, okfn);

    return ret;
}

// we need junkie to call a symbol from this compilation unit
void serialize_init(void) {}
void serialize_fini(void) {}
