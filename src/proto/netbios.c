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
#include "junkie/cpp.h"
#include "junkie/tools/log.h"
#include "junkie/proto/proto.h"
#include "junkie/proto/netbios.h"
#include "junkie/proto/cifs.h"
#include "junkie/proto/tcp.h"
#include "junkie/tools/objalloc.h"
#include "junkie/proto/streambuf.h"

#undef LOG_CAT
#define LOG_CAT proto_netbios_log_category

LOG_CATEGORY_DEF(proto_netbios);

#define NETBIOS_SESSION_MESSAGE 0x00 /* unused yet */
#define NETBIOS_HEADER_SIZE 4

struct netbios_parser {
    struct parser parser;
    struct parser *msg_parser;
    struct streambuf sbuf;
    struct timeval first_packet_tv[2];
};

static parse_fun netbios_sbuf_parse;

static int netbios_parser_ctor(struct netbios_parser *netbios_parser, struct proto *proto)
{
    SLOG(LOG_DEBUG, "Constructing netbios_parser@%p", netbios_parser);
    assert(proto == proto_netbios);
    if (0 != parser_ctor(&netbios_parser->parser, proto)) return -1;
    netbios_parser->msg_parser = NULL;
    timeval_reset(&netbios_parser->first_packet_tv[0]);
    timeval_reset(&netbios_parser->first_packet_tv[1]);
    if (0 != streambuf_ctor(&netbios_parser->sbuf, netbios_sbuf_parse, 30000, NULL)) {
        parser_dtor(&netbios_parser->parser);
        return -1;
    }
    return 0;
}

static struct parser *netbios_parser_new(struct proto *proto)
{
    struct netbios_parser *netbios_parser = objalloc_nice(sizeof(*netbios_parser), "Netbios parsers");
    if (! netbios_parser) return NULL;
    if (-1 == netbios_parser_ctor(netbios_parser, proto)) {
        objfree(netbios_parser);
        return NULL;
    }
    return &netbios_parser->parser;
}

static void netbios_parser_dtor(struct netbios_parser *netbios_parser)
{
    SLOG(LOG_DEBUG, "Destructing netbios_parser@%p", netbios_parser);
    parser_unref(&netbios_parser->msg_parser);
    parser_dtor(&netbios_parser->parser);
    streambuf_dtor(&netbios_parser->sbuf);
}

static void netbios_parser_del(struct parser *parser)
{
    struct netbios_parser *netbios_parser = DOWNCAST(parser, parser, netbios_parser);
    netbios_parser_dtor(netbios_parser);
    objfree(netbios_parser);
}

static void const *netbios_info_addr(struct proto_info const *info_, size_t *size)
{
    struct netbios_proto_info const *info = DOWNCAST(info_, info, netbios_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static void netbios_proto_info_ctor(struct netbios_proto_info *info, struct parser *parser,
        struct proto_info *parent, size_t header, size_t payload, uint32_t size,
        struct timeval const *first_packet_tv)
{
    proto_info_ctor(&info->info, parser, parent, header, payload);
    info->size = size;
    info->first_packet_tv = *first_packet_tv;
}

static enum proto_parse_status netbios_parse_frame(struct netbios_parser *netbios_parser, struct proto_info *parent,
        unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now,
        size_t tot_cap_len, uint8_t const *tot_packet, size_t *pos)
{
    if (!timeval_is_set(&netbios_parser->first_packet_tv[way])) {
        SLOG(LOG_DEBUG, "Set first packet ts for way %d to %s", way, timeval_2_str(now));
        netbios_parser->first_packet_tv[way] = *now;
    }
    if (wire_len < NETBIOS_HEADER_SIZE + 4) {
        streambuf_set_restart(&netbios_parser->sbuf, way, packet, NETBIOS_HEADER_SIZE + 4);
        return PROTO_OK;
    }
    if (cap_len < NETBIOS_HEADER_SIZE + 4) {
        // Last packet might be pending
        streambuf_set_restart(&netbios_parser->sbuf, way, packet, false);
        return PROTO_TOO_SHORT;
    }
    uint32_t smb_version = READ_U32N(packet + NETBIOS_HEADER_SIZE);
    if (smb_version != CIFS_SMB_HEADER && smb_version != CIFS_SMB2_HEADER) {
        SLOG(LOG_DEBUG, "Netbios payload does not expected header (expected %"PRIx32" or %"PRIx32"), got %"PRIx32,
                CIFS_SMB_HEADER, CIFS_SMB2_HEADER, smb_version);
        return PROTO_PARSE_ERR;
    }

    uint32_t len = READ_U32N((uint32_t*) packet) & 0x00ffffff;
    *pos = len;
    size_t current_payload = wire_len - NETBIOS_HEADER_SIZE;
    SLOG(LOG_DEBUG, "Found netbios payload of %"PRIu32", current payload %zu",
            len, current_payload);
    if (len > current_payload) {
        streambuf_set_restart(&netbios_parser->sbuf, way, packet, true);
        return PROTO_OK;
    }

    /* Parse */
    struct netbios_proto_info info;
    netbios_proto_info_ctor(&info, &netbios_parser->parser, parent,
            NETBIOS_HEADER_SIZE, wire_len - NETBIOS_HEADER_SIZE, len,
            netbios_parser->first_packet_tv + way);
    timeval_reset(netbios_parser->first_packet_tv + way);

    SLOG(LOG_DEBUG, "Parsing netbios content");
    uint8_t const *next_packet = packet + NETBIOS_HEADER_SIZE;
    if (!netbios_parser->msg_parser) {
        netbios_parser->msg_parser = proto_cifs->ops->parser_new(proto_cifs);
    }

    enum proto_parse_status status = PROTO_OK;
    if (netbios_parser->msg_parser) {
        status = proto_parse(netbios_parser->msg_parser, &info.info,
                way, next_packet,
                cap_len - NETBIOS_HEADER_SIZE, wire_len - NETBIOS_HEADER_SIZE,
                now, tot_cap_len, tot_packet);
        if (status == PROTO_OK) return PROTO_OK;
    }
    (void)proto_parse(NULL, &info.info, way, next_packet, cap_len - NETBIOS_HEADER_SIZE, wire_len - NETBIOS_HEADER_SIZE, now, tot_cap_len, tot_packet);
    return status;
}

static enum proto_parse_status netbios_sbuf_parse(struct parser *parser, struct proto_info *parent,
        unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len,
        struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct netbios_parser *netbios_parser = DOWNCAST(parser, parser, netbios_parser);
    size_t pos = 0;
    while (wire_len > pos) {
        size_t netbios_payload = 0;
        size_t new_cap_len = cap_len > pos ? cap_len - pos : 0;
        SLOG(LOG_DEBUG, "Parse netbios frame with cap len %zu, wire len %zu, pos %zu (%zu bytes captured, %zu bytes in wire)",
                cap_len, wire_len, pos, new_cap_len, wire_len - pos);
        enum proto_parse_status status = netbios_parse_frame(netbios_parser, parent, way,
                packet + pos, new_cap_len, wire_len - pos, now, tot_cap_len, tot_packet, &netbios_payload);
        if (status != PROTO_OK || netbios_payload == 0) return status;
        pos += netbios_payload + NETBIOS_HEADER_SIZE;
    }
    return PROTO_OK;
}

static enum proto_parse_status netbios_parse(struct parser *parser, struct proto_info *parent,
        unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len,
        struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct netbios_parser *netbios_parser = DOWNCAST(parser, parser, netbios_parser);

    enum proto_parse_status const status = streambuf_add(&netbios_parser->sbuf, parser, parent,
            way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);

    return status;
}


/*
 * Initialization
 */

static struct uniq_proto uniq_proto_netbios;
struct proto *proto_netbios = &uniq_proto_netbios.proto;
static struct port_muxer tcp_port_muxer;

void netbios_init(void)
{
    log_category_proto_netbios_init();

    static struct proto_ops const ops = {
        .parse      = netbios_parse,
        .parser_new = netbios_parser_new,
        .parser_del = netbios_parser_del,
        .info_2_str = proto_info_2_str,
        .info_addr  = netbios_info_addr,
    };
    uniq_proto_ctor(&uniq_proto_netbios, &ops, "Netbios", PROTO_CODE_NETBIOS);
    port_muxer_ctor(&tcp_port_muxer, &tcp_port_muxers, 445, 445, proto_netbios);
}

void netbios_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    port_muxer_dtor(&tcp_port_muxer, &tcp_port_muxers);
    uniq_proto_dtor(&uniq_proto_netbios);
#   endif
    log_category_proto_netbios_fini();
}

