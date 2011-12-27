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
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include "junkie/cpp.h"
#include "junkie/tools/tempstr.h"
#include "junkie/proto/proto.h"
#include "junkie/proto/dns.h"
#include "junkie/proto/tcp.h"


#undef LOG_CAT
#define LOG_CAT proto_dns_log_category

/*
 * Parse
 */

static enum proto_parse_status dns_tcp_parse(struct parser unused_ *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn, size_t tot_cap_len, uint8_t const *tot_packet)
{
    size_t const hlen = 2;
    size_t offset = 0;

    while (offset + hlen < cap_len) {
        size_t len = READ_U16N(packet);
        offset += hlen;

        // Sanity check
        if (offset + len > wire_len) return PROTO_PARSE_ERR;

        struct parser *dns = proto_dns->ops->parser_new(proto_dns);
        if (! dns) break;

        enum proto_parse_status status = proto_parse(dns, parent, way, packet+offset, cap_len-offset, wire_len-offset, now, okfn, tot_cap_len, tot_packet);
        parser_unref(dns);
        if (status != PROTO_OK) break;

        offset += len;
    }

    return PROTO_OK;
}

/*
 * Init
 */

static struct uniq_proto uniq_proto_dns_tcp;
struct proto *proto_dns_tcp = &uniq_proto_dns_tcp.proto;
static struct port_muxer dns_tcp_port_muxer, mdns_tcp_port_muxer, nbns_tcp_port_muxer, llmnr_tcp_port_muxer;

void dns_tcp_init(void)
{
    static struct proto_ops const ops = {
        .parse      = dns_tcp_parse,
        .parser_new = uniq_parser_new,
        .parser_del = uniq_parser_del,
    };
    uniq_proto_ctor(&uniq_proto_dns_tcp, &ops, "DNS/TCP", PROTO_CODE_DNS /* since we share the same info struct */);
    port_muxer_ctor(&dns_tcp_port_muxer, &tcp_port_muxers, DNS_PORT, DNS_PORT, proto_dns_tcp);
    port_muxer_ctor(&mdns_tcp_port_muxer, &tcp_port_muxers, MDNS_PORT, MDNS_PORT, proto_dns_tcp);
    port_muxer_ctor(&nbns_tcp_port_muxer, &tcp_port_muxers, NBNS_PORT, NBNS_PORT, proto_dns_tcp);
    port_muxer_ctor(&llmnr_tcp_port_muxer, &tcp_port_muxers, LLMNR_PORT, LLMNR_PORT, proto_dns_tcp);
}

void dns_tcp_fini(void)
{
    port_muxer_dtor(&llmnr_tcp_port_muxer, &tcp_port_muxers);
    port_muxer_dtor(&nbns_tcp_port_muxer, &tcp_port_muxers);
    port_muxer_dtor(&mdns_tcp_port_muxer, &tcp_port_muxers);
    port_muxer_dtor(&dns_tcp_port_muxer, &tcp_port_muxers);
    uniq_proto_dtor(&uniq_proto_dns_tcp);
}

