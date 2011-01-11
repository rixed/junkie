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
#include <junkie/cpp.h>
#include <junkie/tools/log.h>
#include <junkie/tools/mallocer.h>
#include <junkie/proto/tcp.h>
#include <junkie/proto/sql.h>
#include <junkie/proto/streambuf.h>
#include <junkie/proto/cursor.h>

static char const Id[] = "$Id$";

#define TNS_TIMEOUT (60 * 15)

#undef LOG_CAT
#define LOG_CAT proto_tns_log_category

LOG_CATEGORY_DEF(proto_tns);

struct tns_parser {
	struct parser parser;
	unsigned c2s_way;	// The way when traffic is going from client to server (~0U for unset)
    struct streambuf sbuf;
};

static parse_fun tns_sbuf_parse;

static int tns_parser_ctor(struct tns_parser *tns_parser, struct proto *proto, struct timeval const *now)
{
    assert(proto == proto_tns);
    if (0 != parser_ctor(&tns_parser->parser, proto, now)) return -1;
    tns_parser->c2s_way = ~0U;    // unset
    if (0 != streambuf_ctor(&tns_parser->sbuf, tns_sbuf_parse, 30000)) return -1;

    return 0;
}

static struct parser *tns_parser_new(struct proto *proto, struct timeval const *now)
{
    MALLOCER(tns_parsers);
    struct tns_parser *tns_parser = MALLOC(tns_parsers, sizeof(*tns_parser));
    if (! tns_parser) return NULL;

    if (-1 == tns_parser_ctor(tns_parser, proto, now)) {
        FREE(tns_parser);
        return NULL;
    }

    return &tns_parser->parser;
}

static void tns_parser_dtor(struct tns_parser *tns_parser)
{
    parser_dtor(&tns_parser->parser);
    streambuf_dtor(&tns_parser->sbuf);
}

static void tns_parser_del(struct parser *parser)
{
    struct tns_parser *tns_parser = DOWNCAST(parser, parser, tns_parser);
    tns_parser_dtor(tns_parser);
    FREE(tns_parser);
}

/*
 * Parse
 * Most of this was inspired by Wireshark TNS dissector.
 */

#define TNS_CONNECT    1
#define TNS_ACCEPT     2
#define TNS_ACK        3
#define TNS_REFUSE     4
#define TNS_REDIRECT   5
#define TNS_DATA       6
#define TNS_NULL       7
#define TNS_ABORT      9
#define TNS_RESEND    11
#define TNS_MARKER    12
#define TNS_ATTENTION 13
#define TNS_CONTROL   14
#define TNS_TYPE_MAX  19

#define NET8_TYPE_ROWTRANSFER 6

static enum proto_parse_status cursor_read_tns_hdr(struct cursor *cursor, size_t *len_, unsigned *type_)
{
    /* TNS PDU have a header consisting of (in network byte order) :
     * - a 2 bytes length
     * - a 2 bytes checksum
     * - a one byte type
     * - a one byte 0
     * - a 2 bytes header checksum (or 0) */
    SLOG(LOG_DEBUG, "Reading a TNS PDU");

    CHECK_LEN(cursor, 8, 0);
    size_t len = cursor_read_u16n(cursor);
    if (len < 8) return PROTO_PARSE_ERR;
    len -= 8;
    cursor_drop(cursor, 2);
    unsigned type = cursor_read_u8(cursor);
    cursor_drop(cursor, 3);
    if (type > TNS_TYPE_MAX) return PROTO_PARSE_ERR;

    if (len_) *len_ = len;
    if (type_) *type_ = type;
    return PROTO_OK;
}

static bool is_delim(char c)
{
    return c == ')' || c == '\0'; // what else?
}

static void copy_token(char *dst, size_t dst_len, char const *src, size_t src_len)
{
    while (src_len > 0 && dst_len > 1 && !is_delim(*src)) {
        *dst++ = *src++;
        dst_len --;
        src_len --;
    }
    *dst = '\0';
}

static enum proto_parse_status tns_parse_connect(struct tns_parser unused_ *tns_parser, struct sql_proto_info *info, struct cursor *cursor, size_t pdu_len)
{
    if (! info->is_query) return PROTO_PARSE_ERR;
    SLOG(LOG_DEBUG, "Parsing TNS connect PDU of size %zu", pdu_len);

    info->msg_type = SQL_STARTUP;

    /* A connect is (in network byte order) :
     * - 2 bytes version
     * - 2 bytes back compatibility
     * - 2 bytes service options
     * - 2 bytes session data unit size
     * - 2 bytes max transm. data unit size
     * - 2 bytes proto characteristics
     * - 2 bytes line turnaround
     * - 2 bytes value of one
     * - 2 bytes connect data length
     * - 2 bytes connect data offset
     * - 4 bytes connect data max
     * - 1 byte connect flags 0
     * - 1 byte connect flags 1
     * - optionaly, 16 bytes for trace things
     * - padding until data offset
     * - then connect data */
    if (pdu_len < 26) return PROTO_PARSE_ERR;
    unsigned version = cursor_read_u16n(cursor);
    info->version_maj = version/100;
    info->version_min = version%100;
    info->set_values |= SQL_VERSION;
    cursor_drop(cursor, 14);    // jump to connect data length
    unsigned data_length = cursor_read_u16n(cursor);
    unsigned data_offset = cursor_read_u16n(cursor);
    SLOG(LOG_DEBUG, "Connect, data length=%u, data offset=%u", data_length, data_offset);
    if (data_offset > pdu_len || data_offset < 26 + 8) return PROTO_PARSE_ERR;
    if (data_length + data_offset > pdu_len + 8) return PROTO_PARSE_ERR;
    cursor_drop(cursor, data_offset - 20 - 8);  // jump to data
    // Now look for user and dbname (ie. service_name)
#   define USER_TOKEN "(USER="
#   define DBNAME_TOKEN "(SERVICE_NAME="
    char const *data_end = (char const *)(cursor->head + data_length);
    char const *str;
    if (NULL != (str = strnstr((char const *)cursor->head, USER_TOKEN, data_length))) {
        str += strlen(USER_TOKEN);
        info->set_values |= SQL_USER;
        copy_token(info->u.startup.user, sizeof(info->u.startup.user), str, data_end-str);
    }
    if (NULL != (str = strnstr((char const *)cursor->head, DBNAME_TOKEN, data_length))) {
        str += strlen(DBNAME_TOKEN);
        info->set_values |= SQL_DBNAME;
        copy_token(info->u.startup.dbname, sizeof(info->u.startup.dbname), str, data_end-str);
    }
    return PROTO_OK;
}

static enum proto_parse_status tns_parse_accept(struct tns_parser unused_ *tns_parser, struct sql_proto_info *info, struct cursor *cursor, size_t pdu_len)
{
    if (info->is_query) return PROTO_PARSE_ERR;
    SLOG(LOG_DEBUG, "Parsing TNS accept PDU of size %zu", pdu_len);

    info->msg_type = SQL_STARTUP;

    /* An accept message is constitued of :
     * - 2 bytes version
     * - 2 bytes service options
     * - 2 bytes session data unit size
     * - 2 bytes max transm. data unit size
     * - 2 bytes value of one
     * - 2 bytes data length
     * - 2 bytes data offset
     * - 1 byte connect flag 0
     * - 1 byte connect flag 1 */
    if (pdu_len < 16) return PROTO_PARSE_ERR;
    unsigned version = cursor_read_u16n(cursor);
    info->version_maj = version/100;
    info->version_min = version%100;
    info->set_values |= SQL_VERSION;
    info->u.startup.status = 0;
    info->set_values |= SQL_AUTH_STATUS;
    return PROTO_OK;
}

static void net8_copy_sql(struct sql_proto_info *info, struct cursor *cursor, size_t offset, size_t data_len)
{
    assert(data_len > offset);
    /* The strings are stored like this :
     * - 1 byte length
     * - if length != 0xfe, then follows the string, null terminated
     * - if length = 0xfe, the string is segmented. Each segment is a length then the chars. */
    info->msg_type = SQL_QUERY;
    cursor_drop(cursor, offset);
    data_len -= offset;
    unsigned len = cursor_read_u8(cursor);
    data_len --;
    if (len != 0xfe) {
        snprintf(info->u.query.sql, sizeof(info->u.query.sql), "%.*s", (int)MIN(data_len, len), (char *)cursor->head);
    } else {
        int sql_len = 0;
        do {
            if (data_len < 1) return;
            len = cursor_read_u8(cursor);
            data_len --;
            if (len == 0) break;
            if (len > data_len) return;
            sql_len += snprintf(info->u.query.sql + sql_len, sizeof(info->u.query.sql) - sql_len, "%.*s", (int)MIN(data_len, len), (char *)cursor->head);
            cursor_drop(cursor, len);
        } while (1);
    }
    // replace newlines by spaces
    for (char *c = info->u.query.sql; *c != '\0'; c++) {
        if (*c == '\n' || *c == '\r' || *c == '\t') *c = ' ';
    }
    info->set_values |= SQL_SQL;
}

static enum proto_parse_status tns_parse_data(struct tns_parser unused_ *tns_parser, struct sql_proto_info *info, struct cursor *cursor, size_t pdu_len)
{
    SLOG(LOG_DEBUG, "Parsing TNS data PDU of size %zu", pdu_len);

    // First, read the data flags
    CHECK_LEN(cursor, 2, 0);
    unsigned flags = cursor_read_u16n(cursor);
    SLOG(LOG_DEBUG, "Data flags = 0x%x", flags);
    if (flags & 0x40) { // End Of File
        if (pdu_len != 2) return PROTO_PARSE_ERR;   // This may be wrong, maybe a command is allowed anyway
        info->msg_type = SQL_EXIT;
        return PROTO_OK;
    }
    pdu_len -= 2;

    // Else we try to locate the user's query or the server's response.
    info->msg_type = SQL_QUERY;

    CHECK_LEN(cursor, 1, 1);
    unsigned const header_op = cursor_read_u8(cursor);
    pdu_len --;
    SLOG(LOG_DEBUG, "Header Operation = %u", header_op);

    if (header_op == NET8_TYPE_ROWTRANSFER) {
        if (info->is_query) return PROTO_PARSE_ERR;
        /* then we expect :
         * - 1 byte flags
         * - 1 byte num fields
         * - 1 byte iter num (?)
         * - 2 bytes num iters this time (??)
         * - 2 bytes num rows */
        CHECK_LEN(cursor, 7, 2);
        cursor_drop(cursor, 1); // skip the flags
        info->u.query.nb_fields = cursor_read_u16n(cursor);
        info->set_values |= SQL_NB_FIELDS;
        cursor_drop(cursor, 3); // skip iter things
        info->u.query.nb_rows = cursor_read_u16n(cursor);
        info->set_values |= SQL_NB_ROWS;
    } else if (info->is_query) {
        // Try to locate the command string (ie. at least 8 printable chars)
        unsigned nb_chars = 0;  // nb successive chars
        for (unsigned c = 1; c < pdu_len; c++) {    // we skip one byte for the string length
            if (isprint(cursor->head[c])) {
                if (++nb_chars > 8) {
                    net8_copy_sql(info, cursor, c - nb_chars, pdu_len);
                    break;
                }
            } else {
                nb_chars = 0;
            }
        }
    }

    return PROTO_OK;
}

static enum proto_parse_status tns_sbuf_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn)
{
    struct tns_parser *tns_parser = DOWNCAST(parser, parser, tns_parser);

    // If this is the first time we are called, init c2s_way
    if (tns_parser->c2s_way == ~0U) {
        tns_parser->c2s_way = way;
        SLOG(LOG_DEBUG, "First packet, init c2s_way to %u", tns_parser->c2s_way);
    }

    // Now build the proto_info
    struct sql_proto_info info;
    proto_info_ctor(&info.info, parser, parent, wire_len, 0);
    info.is_query = way == tns_parser->c2s_way;
    info.set_values = 0;
    info.msg_type = SQL_UNKNOWN;

    // and try to read a TNS PDN
    struct cursor cursor;
    cursor_ctor(&cursor, payload, cap_len);

    while (! cursor_is_empty(&cursor)) {
        uint8_t const *const msg_start = cursor.head;
        size_t pdu_len;
        unsigned pdu_type;
        enum proto_parse_status status = cursor_read_tns_hdr(&cursor, &pdu_len, &pdu_type);
        if (status == PROTO_PARSE_ERR) return PROTO_PARSE_ERR;
        if (status == PROTO_TOO_SHORT) {
            SLOG(LOG_DEBUG, "Payload too short for parsing message, will restart");
            streambuf_set_restart(&tns_parser->sbuf, way, msg_start);
            break;  // will ack what we had so far
        }
        uint8_t const *const msg_end = cursor.head + pdu_len;
        switch (pdu_type) {
            case TNS_CONNECT:
                status = tns_parse_connect(tns_parser, &info, &cursor, pdu_len);
            case TNS_ACCEPT:
                status = tns_parse_accept(tns_parser, &info, &cursor, pdu_len);
            case TNS_DATA:
                status = tns_parse_data(tns_parser, &info, &cursor, pdu_len);
            case TNS_REFUSE:
            case TNS_REDIRECT:
            case TNS_ABORT:
            case TNS_MARKER:
            case TNS_ATTENTION:
            case TNS_CONTROL:
            default:    // A type we do not handle, skip the PDU
                break;
        }

        cursor_drop(&cursor, msg_end - cursor.head);
    }

    return proto_parse(NULL, &info.info, way, NULL, 0, 0, now, okfn);
}

static enum proto_parse_status tns_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn)
{
    struct tns_parser *tns_parser = DOWNCAST(parser, parser, tns_parser);

    return streambuf_add(&tns_parser->sbuf, parser, parent, way, payload, cap_len, wire_len, now, okfn);
}

/*
 * Construction/Destruction
 */

static struct proto proto_tns_;
struct proto *proto_tns = &proto_tns_;
static struct port_muxer tns_tcp_muxer;

void tns_init(void)
{
    log_category_proto_tns_init();

    static struct proto_ops const ops = {
        .parse      = tns_parse,
        .parser_new = tns_parser_new,
        .parser_del = tns_parser_del,
        .info_2_str = sql_info_2_str,
        .info_addr  = sql_info_addr,
    };
    proto_ctor(&proto_tns_, &ops, "TNS", TNS_TIMEOUT);
    port_muxer_ctor(&tns_tcp_muxer, &tcp_port_muxers, 1521, 1521, proto_tns);
}

void tns_fini(void)
{
    port_muxer_dtor(&tns_tcp_muxer, &tcp_port_muxers);
    proto_dtor(&proto_tns_);
    log_category_proto_tns_fini();
}
