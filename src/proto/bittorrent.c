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
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <junkie/cpp.h>
#include <junkie/tools/tempstr.h>
#include <junkie/tools/miscmacs.h>
#include <junkie/proto/proto.h>
#include <junkie/proto/tcp.h>
#include <junkie/proto/bittorrent.h>
#include <junkie/tools/log.h>

static char const bittorrent_Id[] = "$Id: bb54fce9fbd42ea3ac1130ba0d0f994a3deaae1a $";

#undef LOG_CAT
#define LOG_CAT proto_bittorrent_log_category

LOG_CATEGORY_DEC(proto_bittorrent);
LOG_CATEGORY_DEF(proto_bittorrent);

/*
 * Parse
 */

// We humbly try to find out if this payload is related to bittorrent protocol
static bool is_bittorrent(uint8_t const *packet, size_t packet_len)
{
#   define STR1 "/announce"
#   define STR2 "BitTorrent Protocol"
    static uint8_t const pattern1[] = { 0x00, 0x00, 0x00, 0x0d, 0x06, 0x00 };
    static uint8_t const pattern2[] = { 0x00, 0x00, 0x40, 0x09, 0x07, 0x00, 0x00, 0x00 };

    return
        (packet_len >= sizeof(pattern1) && 0 == memcmp(pattern1, packet, sizeof(pattern1))) ||
        (packet_len >= sizeof(pattern2) && 0 == memcmp(pattern2, packet, sizeof(pattern2))) ||
        (packet_len >= strlen(STR1) && 0 == strnstr((char const *)packet, STR1, strlen(STR1))) ||
        (packet_len >= strlen(STR2) && 0 == strnstr((char const *)packet, STR2, strlen(STR2)));
}

static enum proto_parse_status bittorrent_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t unused_ wire_len, struct timeval const *now, proto_okfn_t *okfn)
{
    if (! is_bittorrent(packet, cap_len)) return PROTO_PARSE_ERR;

    struct bittorrent_proto_info info;
    proto_info_ctor(&info.info, parser, parent, 0, wire_len);

    return proto_parse(NULL, &info.info, way, NULL, 0, 0, now, okfn);
}

/*
 * Init
 */

static struct uniq_proto uniq_proto_bittorrent;
struct proto *proto_bittorrent = &uniq_proto_bittorrent.proto;
static struct port_muxer tcp_port_muxer;

void bittorrent_init(void)
{
    log_category_proto_bittorrent_init();

    static struct proto_ops const ops = {
        .parse      = bittorrent_parse,
        .parser_new = uniq_parser_new,
        .parser_del = uniq_parser_del,
        .info_2_str = proto_info_2_str,
        .info_addr  = proto_info_addr,
    };
    uniq_proto_ctor(&uniq_proto_bittorrent, &ops, "bittorrent");
    port_muxer_ctor(&tcp_port_muxer, &tcp_port_muxers, 6881, 6999, proto_bittorrent);
}

void bittorrent_fini(void)
{
    port_muxer_dtor(&tcp_port_muxer, &tcp_port_muxers);
    uniq_proto_dtor(&uniq_proto_bittorrent);
    log_category_proto_bittorrent_fini();
}

