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
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include "junkie/cpp.h"
#include "junkie/tools/log.h"
#include "junkie/tools/tempstr.h"
#include "junkie/tools/objalloc.h"
#include "junkie/proto/cursor.h"
#include "junkie/proto/proto.h"
#include "junkie/proto/tcp.h"
#include "junkie/proto/tds.h"
#include "junkie/proto/sql.h"
#include "junkie/proto/streambuf.h"

/* TDS has both notions of messages and packets.
 * Surely, the specifiers though that TDS will conquer TCP, UDP, Wap and the whole world,
 * so this whole packet thing, with its length, negotiated MTU and sequence numbers,
 * was absolutely necessary.
 * Of course tody TDS runs only on top of TCP and these packet headers, according to the
 * spec itself, are unused. As a result we now have a mostly useless header possibly in the
 * way of basic messages.
 * This parser implements this useless half backed transport layer, while the
 * tds_msg parser implements the actual parsing of messages.
 *
 * Note: for greater fun, TLS start being transported by TDS (in packets of
 * pre-login types) to end up transporting TDS.
 */

#undef LOG_CAT
#define LOG_CAT proto_tds_log_category

LOG_CATEGORY_DEF(proto_tds);

struct tds_parser {
    struct parser parser;
    // each tds parser comes with its tds_msg parser
    struct parser *msg_parser;

    struct streambuf sbuf;  // yep, one more level of buffering
};

char const *tds_packet_type_2_str(enum tds_packet_type type)
{
    switch (type) {
        case TDS_PKT_TYPE_SQL_BATCH:   return "SQL batch";
        case TDS_PKT_TYPE_LOGIN:       return "Login";
        case TDS_PKT_TYPE_RPC:         return "RPC";
        case TDS_PKT_TYPE_RESULT:      return "Tabular result";
        case TDS_PKT_TYPE_ATTENTION:   return "Attention signal";
        case TDS_PKT_TYPE_BULK_LOAD:   return "Bulk load data";
        case TDS_PKT_TYPE_MANAGER_REQ: return "Transaction manager request";
        case TDS_PKT_TYPE_TDS7_LOGIN:  return "TDS7 login";
        case TDS_PKT_TYPE_SSPI:        return "SSPI";
        case TDS_PKT_TYPE_PRELOGIN:    return "Pre-login";
    }
    return tempstr_printf("Unknown TDS packet type %u", (unsigned)type);
}

static bool tds_packet_has_data(enum tds_packet_type type)
{
    switch (type) {
        case TDS_PKT_TYPE_SQL_BATCH:
        case TDS_PKT_TYPE_LOGIN:
        case TDS_PKT_TYPE_RPC:
        case TDS_PKT_TYPE_RESULT:
        case TDS_PKT_TYPE_BULK_LOAD:
        case TDS_PKT_TYPE_MANAGER_REQ:
        case TDS_PKT_TYPE_TDS7_LOGIN:
        case TDS_PKT_TYPE_SSPI:
        case TDS_PKT_TYPE_PRELOGIN:
            return true;
        case TDS_PKT_TYPE_ATTENTION:
            return false;
    }
    assert(!"Invalid tds_packet_type");
}

static parse_fun tds_sbuf_parse;

static int tds_parser_ctor(struct tds_parser *tds_parser, struct proto *proto)
{
    SLOG(LOG_DEBUG, "Constructing tds_parser@%p", tds_parser);
    assert(proto == proto_tds);
    if (0 != parser_ctor(&tds_parser->parser, proto)) return -1;
    tds_parser->msg_parser = NULL;
    if (0 != streambuf_ctor(&tds_parser->sbuf, tds_sbuf_parse, 30000)) return -1;

    return 0;
}

static struct parser *tds_parser_new(struct proto *proto)
{
    struct tds_parser *tds_parser = objalloc_nice(sizeof(*tds_parser), "TDS(transp) parsers");
    if (! tds_parser) return NULL;

    if (-1 == tds_parser_ctor(tds_parser, proto)) {
        objfree(tds_parser);
        return NULL;
    }

    return &tds_parser->parser;
}

static void tds_parser_dtor(struct tds_parser *tds_parser)
{
    SLOG(LOG_DEBUG, "Destructing tds_parser@%p", tds_parser);
    parser_unref(&tds_parser->msg_parser);
    parser_dtor(&tds_parser->parser);
    streambuf_dtor(&tds_parser->sbuf);
}

static void tds_parser_del(struct parser *parser)
{
    struct tds_parser *tds_parser = DOWNCAST(parser, parser, tds_parser);
    tds_parser_dtor(tds_parser);
    objfree(tds_parser);
}

/*
 * Proto infos
 */

char const *tds_info_2_str(struct proto_info const *info_)
{
    struct tds_proto_info const *info = DOWNCAST(info_, info, tds_proto_info);
    char *str = tempstr();

    snprintf(str, TEMPSTR_SIZE, "%s, type=%s, status=0x%x",
        proto_info_2_str(info_),
        tds_packet_type_2_str(info->type),
        info->status);
    return str;
}

void const *tds_info_addr(struct proto_info const *info_, size_t *size)
{
    struct tds_proto_info const *info = DOWNCAST(info_, info, tds_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

/*
 * Parse
 */

static enum proto_parse_status tds_parse_header(struct cursor *cursor, enum tds_packet_type *out_type,
        uint8_t *out_status, size_t *out_len, bool *unknown_token)
{
#   define TDS_PKT_HDR_LEN 8
    CHECK_LEN(cursor, TDS_PKT_HDR_LEN, 0);

    enum tds_packet_type type = cursor_read_u8(cursor);
    uint8_t status = cursor_read_u8(cursor);
    size_t len = cursor_read_u16n(cursor);
    SLOG(LOG_DEBUG, "Reading new TDS packet of type %s, status %"PRIu8", length %zu", tds_packet_type_2_str(type), status, len);

    // sanity check
    if (len < TDS_PKT_HDR_LEN) return PROTO_PARSE_ERR;
    // Drop rest of header
    cursor_drop(cursor, 4);
    switch (type) {
        case TDS_PKT_TYPE_SQL_BATCH:
        case TDS_PKT_TYPE_LOGIN:
        case TDS_PKT_TYPE_RPC:
        case TDS_PKT_TYPE_RESULT:
        case TDS_PKT_TYPE_ATTENTION:
        case TDS_PKT_TYPE_BULK_LOAD:
        case TDS_PKT_TYPE_MANAGER_REQ:
        case TDS_PKT_TYPE_TDS7_LOGIN:
        case TDS_PKT_TYPE_SSPI:
        case TDS_PKT_TYPE_PRELOGIN:
            break;
        default:
            SLOG(LOG_DEBUG, "Unknown tds type %u", type);
            if (unknown_token) *unknown_token = true;
            return PROTO_PARSE_ERR;
    }
    size_t data_left = len - TDS_PKT_HDR_LEN;
    if ((data_left > 0) != tds_packet_has_data(type)) {
        SLOG(LOG_DEBUG, "This TDS packet of type %s has %zu bytes of data, but should%s have data",
                tds_packet_type_2_str(type), data_left, tds_packet_has_data(type) ? "":" not");
        return PROTO_PARSE_ERR;
    }
    if (out_type) *out_type = type;
    if (out_status) *out_status = status;
    if (out_len) *out_len = len;
    return PROTO_OK;
}

static enum proto_parse_status tds_sbuf_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct tds_parser *tds_parser = DOWNCAST(parser, parser, tds_parser);

    struct cursor cursor;
    cursor_ctor(&cursor, payload, cap_len);

    enum tds_packet_type type;
    uint8_t tds_status;
    size_t len;
    bool unknown_token = false;
    enum proto_parse_status status = tds_parse_header(&cursor, &type, &tds_status, &len, &unknown_token);

    if (status != PROTO_OK) {
        // We have an unknown token if the payload is encrypted after a ssl handshake
        // It is valid but we don't know how to parse it yet
        // TODO It would be better if we knew the values of the encryption options exchanged in prelogin messages
        if (unknown_token) return PROTO_OK;
        return status;
    }

    size_t data_left = len - 8;
    if (data_left > wire_len) {
        streambuf_set_restart(&tds_parser->sbuf, way, payload, true);
        return PROTO_OK;
    }

    struct tds_proto_info info;
    proto_info_ctor(&info.info, parser, parent, TDS_PKT_HDR_LEN, len - TDS_PKT_HDR_LEN);
    info.type = type;
    info.status = tds_status;

    SLOG(LOG_DEBUG, "Parsing %s of size %zu", tds_packet_type_2_str(type), len);
    if (! tds_parser->msg_parser) tds_parser->msg_parser = proto_tds_msg->ops->parser_new(proto_tds_msg);
    if (tds_parser->msg_parser) {
        enum proto_parse_status status = proto_parse(tds_parser->msg_parser, &info.info, way, cursor.head, cursor.cap_len,
                wire_len - TDS_PKT_HDR_LEN, now, tot_cap_len, tot_packet);
        if (status != PROTO_OK) return status;
    }

    // Advertise this packet if it was not done already
    return proto_parse(NULL, &info.info, way, cursor.head, cursor.cap_len, wire_len, now, tot_cap_len, tot_packet);
    return PROTO_OK;
}

static enum proto_parse_status tds_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct tds_parser *tds_parser = DOWNCAST(parser, parser, tds_parser);

    if (cap_len == 0 && wire_len > 0) return PROTO_TOO_SHORT;   // We do not know how to handle pure gaps
    enum proto_parse_status const status = streambuf_add(&tds_parser->sbuf, parser, parent, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);

    return status;
}


/*
 * Construction/Destruction
 */

static struct proto proto_tds_;
struct proto *proto_tds = &proto_tds_;
static struct port_muxer tds_tcp_muxer;

void tds_init(void)
{
    log_category_proto_tds_init();

    static struct proto_ops const ops = {
        .parse       = tds_parse,
        .parser_new  = tds_parser_new,
        .parser_del  = tds_parser_del,
        .info_2_str  = tds_info_2_str,
        .info_addr   = tds_info_addr
    };
    proto_ctor(&proto_tds_, &ops, "TDS", PROTO_CODE_TDS);
    port_muxer_ctor(&tds_tcp_muxer, &tcp_port_muxers, 1433, 1433, proto_tds);
}

void tds_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    port_muxer_dtor(&tds_tcp_muxer, &tcp_port_muxers);
    proto_dtor(&proto_tds_);
#   endif
    log_category_proto_tds_fini();
}

