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
#include <stdbool.h>
#include <ctype.h>
#include "junkie/cpp.h"
#include "junkie/tools/log.h"
#include "junkie/tools/tempstr.h"
#include "junkie/tools/objalloc.h"
#include "junkie/proto/proto.h"
#include "junkie/proto/tcp.h"
#include "junkie/proto/tds.h"
#include "junkie/proto/sql.h"
#include "junkie/proto/streambuf.h"
#include "junkie/proto/cursor.h"

// Use same logger as TDS 'transport'
#undef LOG_CAT
#define LOG_CAT proto_tds_log_category

struct tds_msg_parser {
    struct parser parser;
    unsigned c2s_way;       // The way when traffic is going from client to server (or UNSET)
    enum sql_msg_type last_client_msg_type;
    // A flag giving precious information on how to decode some values (see MSTDS, 2.2.6.3)
#   define F_BYTEORDER 0x01
#   define F_CHAR      0x02
#   define F_FLOAT     0x0C // 2 bits
#   define F_DUMPLOAD  0x10
#   define F_USE_DB    0x20
#   define F_DATABASE  0x40
#   define F_SET_LANG  0x80
    uint8_t option_flag_1;
    struct streambuf sbuf;  // yep, one more level of buffering
};

static parse_fun tds_msg_sbuf_parse;

static int tds_msg_parser_ctor(struct tds_msg_parser *tds_msg_parser, struct proto *proto)
{
    SLOG(LOG_DEBUG, "Constructing tds_msg_parser@%p", tds_msg_parser);
    assert(proto == proto_tds_msg);
    if (0 != parser_ctor(&tds_msg_parser->parser, proto)) return -1;
    tds_msg_parser->c2s_way = UNSET;
    tds_msg_parser->last_client_msg_type = SQL_UNKNOWN;
    tds_msg_parser->option_flag_1 = 0;  // ASCII + LittleEndian by default
    if (0 != streambuf_ctor(&tds_msg_parser->sbuf, tds_msg_sbuf_parse, 30000)) return -1;

    return 0;
}

static struct parser *tds_msg_parser_new(struct proto *proto)
{
    struct tds_msg_parser *tds_msg_parser = objalloc_nice(sizeof(*tds_msg_parser), "TDS(msg) parsers");
    if (! tds_msg_parser) return NULL;

    if (-1 == tds_msg_parser_ctor(tds_msg_parser, proto)) {
        objfree(tds_msg_parser);
        return NULL;
    }

    return &tds_msg_parser->parser;
}

static void tds_msg_parser_dtor(struct tds_msg_parser *tds_msg_parser)
{
    SLOG(LOG_DEBUG, "Destructing tds_msg_parser@%p", tds_msg_parser);
    parser_dtor(&tds_msg_parser->parser);
    streambuf_dtor(&tds_msg_parser->sbuf);
}

static void tds_msg_parser_del(struct parser *parser)
{
    struct tds_msg_parser *tds_msg_parser = DOWNCAST(parser, parser, tds_msg_parser);
    tds_msg_parser_dtor(tds_msg_parser);
    objfree(tds_msg_parser);
}

/*
 * Parse
 *
 * First we start by many small decoding function from cursor to custom types,
 * mapping the names and types used by TDS specifications (so don't blame me
 * for lack of consistency). All these functions depends on the data being
 * available (check for lengths are performed struct by struct, which is more
 * efficient for fixed sized messages/blocs).
 *
 * Then follow message parsing per se.
 */

#define CHARBINLEN_MAX 8000
static uint_least8_t tds_byte(struct cursor *cursor) { return cursor_read_u8(cursor); }
static uint_least8_t tds_bytelen(struct cursor *cursor) { return cursor_read_u8(cursor); }
static uint_least8_t tds_uchar(struct cursor *cursor) { return cursor_read_u8(cursor); }
static uint_least8_t tds_precision(struct cursor *cursor) { return cursor_read_u8(cursor); }
static uint_least8_t tds_scale(struct cursor *cursor) { return cursor_read_u8(cursor); }
static uint_least8_t tds_gen_null(struct cursor *cursor) { return cursor_read_u8(cursor); } // caller must check it's 0
static uint_least16_t tds_ushort(struct cursor *cursor) { return cursor_read_u16le(cursor); }
static uint_least16_t tds_ushortlen(struct cursor *cursor) { return cursor_read_u16le(cursor); }
static uint_least16_t tds_ushortcharbinlen(struct cursor *cursor) { return cursor_read_u16le(cursor); } // caller must check it's bellow CHARBINLEN_MAX
static uint_least16_t tds_unicodechar(struct cursor *cursor) { return cursor_read_u16le(cursor); }
static int_least32_t tds_longlen(struct cursor *cursor) { return cursor_read_u32le(cursor); }
static int_least32_t tds_long(struct cursor *cursor) { return cursor_read_u32le(cursor); }
static uint_least32_t tds_ulong(struct cursor *cursor) { return cursor_read_u32le(cursor); }
static uint_least32_t tds_dword(struct cursor *cursor) { return cursor_read_u32le(cursor); }
static int_least64_t tds_longlong(struct cursor *cursor) { return cursor_read_u64le(cursor); }
static uint_least64_t tds_ulonglong(struct cursor *cursor) { return cursor_read_u64le(cursor); }
static uint_least64_t tds_ulonglonglen(struct cursor *cursor) { return cursor_read_u64le(cursor); }


#define CHECK(n) CHECK_LEN(cursor, n, 0)

static enum proto_parse_status tds_prelogin(struct cursor *cursor, struct sql_proto_info *info)
{
    SLOG(LOG_DEBUG, "Parsing PRE-LOGIN");
    assert(info->msg_type == SQL_STARTUP);
    enum proto_parse_status status = PROTO_PARSE_ERR;

    /* TODO: prelogin messages can also be TLS handshake. */
    enum tds_pl_option_token {
        TDS_VERSION = 0,
        TDS_ENCRYPTION,
        TDS_INSTOPT,
        TDS_THREADID,
        TDS_MARS,
        TDS_TRACEID,
        TDS_TERMINATOR = 0xff
    };

    // all option offsets are relative to this address (start of msg):
    uint8_t const *msg_start = cursor->head;
    uint8_t const *msg_end = cursor->head + cursor->cap_len;    // at most
    while (1) {
        // Read next option + fetch its data
        CHECK(1);
        enum tds_pl_option_token token = cursor_read_u8(cursor);
        if (token == TDS_TERMINATOR) {
            SLOG(LOG_DEBUG, "Found option terminator");
            status = PROTO_OK;
            break;
        }
        CHECK(4);
        size_t offset = cursor_read_u16n(cursor);
        size_t size = cursor_read_u16n(cursor);
        SLOG(LOG_DEBUG, "Found option token %u, at offset %zu, size %zu", token, offset, size);
        struct cursor value;
        cursor_ctor(&value, msg_start + offset, size);
        // Sanity checks
        if (size > 0) {
            if (value.head <= cursor->head || /* <= since we have not read the terminator yet */
                value.head + value.cap_len > msg_end) break;
        }
        // Read value
        switch (token) {
            case TDS_VERSION:   // fetch version
                if (size != 6) return PROTO_PARSE_ERR;
                info->version_maj = cursor_read_u8(&value);
                info->version_min = cursor_read_u8(&value);
                // The rest of version 'string' is not important
                info->set_values |= SQL_VERSION;
                break;
            case TDS_ENCRYPTION:
                if (size != 1) return PROTO_PARSE_ERR;
                enum tds_encryption_option {
                    TDS_ENCRYPT_OFF,
                    TDS_ENCRYPT_ON,
                    TDS_ENCRYPT_NOT_SUP,
                    TDS_ENCRYPT_REQ,
                };
                // See MS-TDS 2.2.6.4
                switch (*value.head) {
                    case TDS_ENCRYPT_ON:
                        info->u.startup.ssl_request = SQL_SSL_REQUESTED;
                        info->set_values |= SQL_SSL_REQUEST;
                        break;
                    case TDS_ENCRYPT_OFF:
                    case TDS_ENCRYPT_NOT_SUP:
                        break;
                    case TDS_ENCRYPT_REQ:
                    default:
                        return PROTO_PARSE_ERR;
                }
                break;
            default:
                SLOG(LOG_DEBUG, "Skipping token...");
                break;
        }
    }

    return status;
}

// TODO: one day, take into account option_flag_1 to decode EBCDIC and whether unicode chars are LE or BE?
static enum proto_parse_status extract_string(char *dst, size_t max_sz, struct cursor *cursor, uint8_t const *msg_start, uint8_t const *msg_end)
{
    // We must read offset then length (LE)
    CHECK(4);
    size_t offset = cursor_read_u16le(cursor);
    size_t size = cursor_read_u16le(cursor);
    // Sanity check
    if (size > 0) {
        if ((ssize_t)offset < cursor->head - msg_start ||
            msg_start + offset + size > msg_end) return PROTO_PARSE_ERR;
    }
    SLOG(LOG_DEBUG, "Extracting a string of size %zu", size);
    if (size > max_sz-1) size = max_sz-1;   // so we will have space for the nul byte to terminate the string
    // Read the string as UNICODE into ASCII
    while (size -- > 0) *dst ++ = msg_start[offset++];
    *dst = '\0';

    return PROTO_OK;
}

static enum proto_parse_status tds_login7(struct tds_msg_parser *tds_msg_parser, struct cursor *cursor, struct sql_proto_info *info)
{
    SLOG(LOG_DEBUG, "Parsing PRE-LOGIN");
    assert(info->msg_type == SQL_STARTUP);

    // all option offsets are relative to this address (start of msg):
    uint8_t const *msg_start = cursor->head;
    uint8_t const *msg_end = cursor->head + cursor->cap_len;    // at most

    /* Login requests starts with many several fixed size fields,
     * first of which being the total length. Other interresting
     * fields include:
     * - OptionFlag1, which tells if client speak BE or LE, ASCII or EBCDIC,
     * and so on,
     * - UserName, Password, ServerName for the sql_startup infos
     * We skip everything else.
     * */
    CHECK(4);
    size_t length = cursor_read_u32le(cursor);
    if (length < 36 || (ssize_t)length > msg_end-msg_start) return PROTO_PARSE_ERR;
    // Note: no offset+len will be allowed after length

    // Go for OptionFlag1
    cursor_drop(cursor, 20);
    tds_msg_parser->option_flag_1 = cursor_read_u8(cursor);

    // Go for UserName
    enum proto_parse_status status;
    cursor_drop(cursor, 11 + 4 /* Skip HostName */);
    if (PROTO_OK != (status = extract_string(info->u.startup.user, sizeof(info->u.startup.user), cursor, msg_start, msg_end))) return status;
    info->set_values |= SQL_USER;
    // Password
    if (PROTO_OK != (status = extract_string(info->u.startup.passwd, sizeof(info->u.startup.passwd), cursor, msg_start, msg_end))) return status;
    // TODO: unscramble it
    info->set_values |= SQL_PASSWD;
    // DBNAME
    cursor_drop(cursor, 4 /* Skip AppName */);
    if (PROTO_OK != (status = extract_string(info->u.startup.dbname, sizeof(info->u.startup.dbname), cursor, msg_start, msg_end))) return status;
    info->set_values |= SQL_DBNAME;

    SLOG(LOG_DEBUG, "LOGIN7 with user=%s, passwd=%s, dbname=%s", info->u.startup.user, info->u.startup.passwd, info->u.startup.dbname);

    return status;
}

static enum sql_msg_type sql_msg_type_of_tds_msg(enum tds_packet_type type, enum sql_msg_type last_client_msg_type)
{
    switch (type) {
        case TDS_PKT_TYPE_SQL_BATCH:
        case TDS_PKT_TYPE_RPC:
        case TDS_PKT_TYPE_BULK_LOAD:
            return SQL_QUERY;
        case TDS_PKT_TYPE_SSPI:
        case TDS_PKT_TYPE_PRELOGIN:
        case TDS_PKT_TYPE_LOGIN:
        case TDS_PKT_TYPE_TDS7_LOGIN:
            return SQL_STARTUP;
        case TDS_PKT_TYPE_ATTENTION:
        case TDS_PKT_TYPE_MANAGER_REQ:
            return SQL_UNKNOWN;
        case TDS_PKT_TYPE_RESULT:
            /* Here we go: all msgs from server to clients are "result", which meaning depends on when it's encountered
             * To sort this out we merely keep the last msg type from client to server and copy it for the response. */
            return last_client_msg_type;
    }

    return SQL_UNKNOWN;
}

// return the direction for client->server
static unsigned c2s_way_of_tds_msg_type(enum tds_packet_type type, unsigned current_way)
{
    switch (type) {
        case TDS_PKT_TYPE_SQL_BATCH:
        case TDS_PKT_TYPE_LOGIN:
        case TDS_PKT_TYPE_RPC:
        case TDS_PKT_TYPE_ATTENTION:
        case TDS_PKT_TYPE_BULK_LOAD:
        case TDS_PKT_TYPE_MANAGER_REQ:
        case TDS_PKT_TYPE_TDS7_LOGIN:
        case TDS_PKT_TYPE_SSPI:
        case TDS_PKT_TYPE_PRELOGIN:
            return current_way;
        case TDS_PKT_TYPE_RESULT:
            return !current_way;
    }

    return current_way; // in doubt, first packet is probably from client
}

static enum proto_parse_status tds_msg_sbuf_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct tds_msg_parser *tds_msg_parser = DOWNCAST(parser, parser, tds_msg_parser);

    // Retrieve TDS infos
    ASSIGN_INFO_CHK(tds, parent, PROTO_PARSE_ERR);

    // If this is the first time we are called, init c2s_way
    if (tds_msg_parser->c2s_way == UNSET) {
        tds_msg_parser->c2s_way = c2s_way_of_tds_msg_type(tds->type, way);
        SLOG(LOG_DEBUG, "First packet, init c2s_way to %u", tds_msg_parser->c2s_way);
    }

    // Now build the proto_info
    struct sql_proto_info info;
    proto_info_ctor(&info.info, parser, parent, wire_len, 0);
    info.is_query = way == tds_msg_parser->c2s_way;
    info.msg_type = sql_msg_type_of_tds_msg(tds->type, tds_msg_parser->last_client_msg_type);
    SLOG(LOG_DEBUG, "msg type = %u (last = %u, TDS type = %u)", info.msg_type, tds_msg_parser->last_client_msg_type, tds->type);
    if (way == tds_msg_parser->c2s_way) tds_msg_parser->last_client_msg_type = info.msg_type;
    info.set_values = 0;

    /* FIXME: We'd like a parser (here: TDS) to inform its subparsers (here: this parser) of PDU boundaries...
     *        For instance, with an additional parse() argument 'boundaries' telling us if we are at the
     *        start of a PDU (or not, or unknown) and if we are at the end. */
    if (tds->tot_msg_size > wire_len || ! (tds->status & TDS_EOM)) {
        // We have not the whole message yet
        streambuf_set_restart(&tds_msg_parser->sbuf, way, payload, true);
        return proto_parse(NULL, &info.info, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);
    }

    struct cursor cursor;
    cursor_ctor(&cursor, payload, cap_len);

    enum proto_parse_status status = PROTO_PARSE_ERR;

    switch (tds->type) {
        case TDS_PKT_TYPE_TDS7_LOGIN:
            status = tds_login7(tds_msg_parser, &cursor, &info);
            break;
        case TDS_PKT_TYPE_LOGIN:
        case TDS_PKT_TYPE_SQL_BATCH:
        case TDS_PKT_TYPE_RPC:
        case TDS_PKT_TYPE_RESULT:
        case TDS_PKT_TYPE_ATTENTION:
        case TDS_PKT_TYPE_BULK_LOAD:
        case TDS_PKT_TYPE_MANAGER_REQ:
        case TDS_PKT_TYPE_SSPI:
            SLOG(LOG_DEBUG, "Don't know how to parse a TDS msg of type %s", tds_packet_type_2_str(tds->type));
            status = PROTO_OK;
            break;
        case TDS_PKT_TYPE_PRELOGIN:
            status = tds_prelogin(&cursor, &info);
            break;
    }

    if (status != PROTO_OK) return status;
    return proto_parse(NULL, &info.info, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);
}

static enum proto_parse_status tds_msg_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct tds_msg_parser *tds_msg_parser = DOWNCAST(parser, parser, tds_msg_parser);

    enum proto_parse_status const status = streambuf_add(&tds_msg_parser->sbuf, parser, parent, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);

    return status;
}

/*
 * Construction/Destruction
 */

static struct proto proto_tds_msg_;
struct proto *proto_tds_msg = &proto_tds_msg_;

void tds_msg_init(void)
{
    static struct proto_ops const ops = {
        .parse       = tds_msg_parse,
        .parser_new  = tds_msg_parser_new,
        .parser_del  = tds_msg_parser_del,
        .info_2_str  = sql_info_2_str,
        .info_addr   = sql_info_addr
    };
    proto_ctor(&proto_tds_msg_, &ops, "TDS(msg)", PROTO_CODE_TDS_MSG);
}

void tds_msg_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    proto_dtor(&proto_tds_msg_);
#   endif
}
