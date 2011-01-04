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
#include <junkie/tools/tempstr.h>
#include <junkie/tools/miscmacs.h>
#include <junkie/proto/proto.h>
#include <junkie/proto/tcp.h>
#include <junkie/proto/ssl.h>
#include <junkie/cpp.h>
#include <junkie/tools/log.h>

static char const ssl_Id[] = "$Id: ff47704a50c73c27351f09b954f78b1fff8aeda4 $";

#undef LOG_CAT
#define LOG_CAT proto_ssl_log_category

LOG_CATEGORY_DEC(proto_ssl);
LOG_CATEGORY_DEF(proto_ssl);

/*
 * ssl_mode
 */

char const *ssl_mode_2_str(enum ssl_mode mode)
{
    switch (mode) {
        case SSL_UNSET: return "UNSET";
        case SSL_v2:    return "v2";
        case SSL_v3:    return "v3";
        case SSL_TLS:   return "TLS";
    }
    FAIL("Invalid SSL mode (%d)", mode);
    return "INVALID";
}

/*
 * Proto Infos
 */

static void const *ssl_info_addr(struct proto_info const *info_, size_t *size)
{
    struct ssl_proto_info const *info = DOWNCAST(info_, info, ssl_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *ssl_info_2_str(struct proto_info const *info_)
{
    struct ssl_proto_info const *info = DOWNCAST(info_, info, ssl_proto_info);
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "%s, mode=%s",
        proto_info_2_str(info_),
        ssl_mode_2_str(info->mode));
    return str;
}

static void ssl_proto_info_ctor(struct ssl_proto_info *info, struct parser *parser, struct proto_info *parent, size_t head_len, size_t payload, enum ssl_mode mode)
{
    proto_info_ctor(&info->info, parser, parent, head_len, payload);

    info->mode = mode;
}

/*
 * Parse
 */

/*
 *  ---->     SYN      ---->
 *  <---    SYN/ACK   <----
 *  ---->     ACK      ---->
 *  ----> ClientHello  ---->
 *  <---  ServerHello <----
 */

static int session_is_sslv2(uint8_t const *packet, size_t packet_len)
{
    if (packet_len > 2 && (packet[0] >> 6 && 3) == 1) {
        uint16_t l = (((uint16_t)(packet[0] & 0x3f)) << 8) + packet[1];
        return l == packet_len && packet[2] == 4;
    }
    return 0;
}

static int session_is_sslv3(uint8_t const *packet, size_t packet_len)
{
    return packet_len > 2 && packet[0] == 23 && packet[1] == 3 && packet[2] == 0;
}

static int session_is_tls(uint8_t const *packet, size_t packet_len)
{
    return packet_len > 2 && packet[0] == 23 && packet[1] == 3 && packet[2] == 1;
}

static enum proto_parse_status ssl_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn)
{
    size_t const head_len = 3; // 3 bytes in the minimum size to tag a flow as ssl

    // Sanity checks
    if (wire_len < head_len) return PROTO_PARSE_ERR;
    if (cap_len < head_len) return PROTO_TOO_SHORT;

    enum ssl_mode mode;
    if (session_is_sslv2(packet, cap_len)) {
        mode = SSL_v2;
    } else if (session_is_sslv3(packet, cap_len)) {
        mode = SSL_v3;
    } else if (session_is_tls(packet, cap_len)) {
        mode = SSL_TLS;
    } else {
        return PROTO_PARSE_ERR;
    }

    // Parse

    struct ssl_proto_info info;
    ssl_proto_info_ctor(&info, parser, parent, head_len, wire_len - head_len, mode);

    return proto_parse(NULL, &info.info, way, NULL, 0, 0, now, okfn);
}

/*
 * Init
 */

static struct uniq_proto uniq_proto_ssl;
struct proto *proto_ssl = &uniq_proto_ssl.proto;
static struct port_muxer tcp_port_muxer;

void ssl_init(void)
{
    log_category_proto_ssl_init();

    static struct proto_ops const ops = {
        .parse      = ssl_parse,
        .parser_new = uniq_parser_new,
        .parser_del = uniq_parser_del,
        .info_2_str = ssl_info_2_str,
        .info_addr  = ssl_info_addr,
    };
    uniq_proto_ctor(&uniq_proto_ssl, &ops, "SSL");
    port_muxer_ctor(&tcp_port_muxer, &tcp_port_muxers, 443, 443, proto_ssl);
}

void ssl_fini(void)
{
    port_muxer_dtor(&tcp_port_muxer, &tcp_port_muxers);
    uniq_proto_dtor(&uniq_proto_ssl);
    log_category_proto_ssl_fini();
}

