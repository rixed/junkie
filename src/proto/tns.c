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
#include "junkie/tools/string_buffer.h"
#include "junkie/tools/log.h"
#include "junkie/tools/string.h"
#include "junkie/tools/objalloc.h"
#include "junkie/proto/tcp.h"
#include "junkie/proto/sql.h"
#include "junkie/proto/streambuf.h"
#include "junkie/proto/cursor.h"

#undef LOG_CAT
#define LOG_CAT proto_tns_log_category

LOG_CATEGORY_DEF(proto_tns);

enum tns_type {
    TNS_CONNECT   =  1,
    TNS_ACCEPT    =  2,
    TNS_ACK       =  3,
    TNS_REFUSE    =  4,
    TNS_REDIRECT  =  5,
    TNS_DATA      =  6,
    TNS_NULL      =  7,
    TNS_ABORT     =  9,
    TNS_RESEND    = 11,
    TNS_MARKER    = 12,
    TNS_ATTENTION = 13,
    TNS_CONTROL   = 14,
    TNS_TYPE_MAX  = 15
};

enum ttc_code {
    TTC_LOGIN_PROPERTY         = 0x01,
    TTC_DATA_REPRESENTATION    = 0x02,
    TTC_QUERY                  = 0x03,
    TTC_END_MESSAGE            = 0x04,
    TTC_ROW_PREFIX             = 0x06,
    TTC_ROW_DATA               = 0x07,
    TTC_ROW_DESCRIPTION        = 0x08,
    TTC_ROW_DESCRIPTION_PREFIX = 0x10,
    TTC_CLOSE                  = 0x11,
    TTC_ROW_RECAP              = 0x15,
    TTC_DEADBEEF               = 0xde,
};

enum query_subcode {
    TTC_QUERY_FETCH         = 0x05,
    TTC_QUERY_ALL_7         = 0x47,
    TTC_QUERY_SQL           = 0x5e,
    TTC_CLOSE_STATEMENT     = 0x69,
};

struct tns_parser {
    struct parser parser;
    unsigned c2s_way;   // The way when traffic is going from client to server (UNSET for unset)
    struct streambuf sbuf;
    unsigned nb_fields; // Keep number of fields for query response
    enum sql_msg_type msg_type;
    struct timeval first_ts;
};

static parse_fun tns_sbuf_parse;

static int tns_parser_ctor(struct tns_parser *tns_parser, struct proto *proto)
{
    assert(proto == proto_tns);
    if (0 != parser_ctor(&tns_parser->parser, proto)) return -1;
    tns_parser->c2s_way = UNSET;    // unset
    tns_parser->nb_fields = UNSET;
    tns_parser->msg_type = SQL_UNKNOWN;
    timeval_reset(&tns_parser->first_ts);
    if (0 != streambuf_ctor(&tns_parser->sbuf, tns_sbuf_parse, 30000, NULL)) return -1;

    return 0;
}

static struct parser *tns_parser_new(struct proto *proto)
{
    struct tns_parser *tns_parser = objalloc_nice(sizeof(*tns_parser), "TNS parsers");
    if (! tns_parser) return NULL;

    if (-1 == tns_parser_ctor(tns_parser, proto)) {
        objfree(tns_parser);
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
    objfree(tns_parser);
}

/*
 * Parse
 * Most of this was inspired by Wireshark TNS dissector.
 */

#define DROP_VAR_STR(cursor)                                                        \
    if ((status = cursor_read_variable_string(cursor, NULL, 0, NULL) != PROTO_OK))     \
        return status;

#define DROP_VAR_STRS(cursor, count)                                                \
    for (unsigned x = 0; x < count; x++) {                                          \
        if ((status = cursor_read_variable_string(cursor, NULL, 0, NULL) != PROTO_OK)) \
        return status;                                                              \
    }

#define DROP_VAR(cursor)                                                            \
    if ((status = cursor_read_variable_int(cursor, NULL) != PROTO_OK))              \
        return status;

#define DROP_VARS(cursor, count)                                                    \
    for(unsigned x = 0; x < count; x++) {                                           \
        if ((status = cursor_read_variable_int(cursor, NULL) != PROTO_OK))          \
        return status;                                                              \
    }

#define DROP_FIX(cursor, len)                                                       \
    if (cursor->cap_len < len)                                                      \
        return PROTO_PARSE_ERR;                                                     \
    cursor_drop(cursor, len);

#define MAX_OCI_CHUNK 0x40

#define DROP_DALC(cursor)                                                                \
    if ((status = cursor_read_chunked_string_with_size(cursor, NULL, 0, MAX_OCI_CHUNK) != PROTO_OK)) \
        return status;

/* TNS PDU have a header consisting of (in network byte order) :
 *
 * | 2 bytes | 2 bytes  | 1 byte | 1 byte | 2 bytes         |
 * | Length  | Checksum | Type   | a zero | Header checksum |
 */
static enum proto_parse_status cursor_read_tns_hdr(struct cursor *cursor, size_t *out_len, unsigned *out_type, size_t wire_len)
{
    SLOG(LOG_DEBUG, "Reading a TNS PDU");

    CHECK_LEN(cursor, 8, 0);
    size_t len = cursor_read_u16n(cursor);
    if (len < 8 || len < wire_len) return PROTO_PARSE_ERR;
    len -= 8;
    SLOG(LOG_DEBUG, "TNS PDU len == %zu", len);
    // Checksum should be 0
    uint_least16_t checksum = cursor_read_u16n(cursor);
    if (checksum > 0) {
        SLOG(LOG_DEBUG, "Tns checksum should be 0, got %u", checksum);
        return PROTO_PARSE_ERR;
    }
    unsigned type = cursor_read_u8(cursor);
    if (type >= TNS_TYPE_MAX) {
        SLOG(LOG_DEBUG, "Tns type invalid, sould be < %u, got %u", TNS_TYPE_MAX, type);
        return PROTO_PARSE_ERR;
    }
    // reserved byte and header checksum should be 0
    uint_least32_t head_checksum =cursor_read_u24(cursor);
    if (head_checksum  > 0) {
        SLOG(LOG_DEBUG, "Reserved byte and checksum should be 0, got %u", head_checksum);
        return PROTO_PARSE_ERR;
    }

    if (out_len) *out_len = len;
    if (out_type) *out_type = type;

    // Check we have the msg payload
    CHECK(len);

    return PROTO_OK;
}

/* Read a string prefixed by 1 byte size
 * Size  String-------------
 * 0x04  0x41 0x42 0x42 0x40
 */
static enum proto_parse_status cursor_read_variable_string(struct cursor *cursor,
        char *buf, size_t size_buf, unsigned *out_str_len)
{
    unsigned str_len;
    CHECK(1);
    str_len = cursor_read_u8(cursor);
    SLOG(LOG_DEBUG, "Reading variable str of length %d", str_len);
    if (out_str_len) *out_str_len = str_len;
    int ret = cursor_read_fixed_string(cursor, buf, size_buf, str_len);
    if (ret == -1) return PROTO_TOO_SHORT;
    else return PROTO_OK;
}

/* Read a string splitted in chunk prefixed by 1 byte size
 * Chunk have a maximum size of 0x40 bytes
 * If there are more than one chunk, a 0x00 end it
 *
 * a multi chunked string
 *
 * Size  String---------    Size  String  End
 * 0x40  0x41 0x42 0x..     0x01  0x49    0x00
 *
 * a single chunked string
 *
 * Size  String---------
 * 0x20  0x41 0x42 0x..
 *
 * The global size might be unknown, so we try to guess it. We will have a parse problem
 * for string of size 0x40
 */
static enum proto_parse_status cursor_read_chunked_string(struct cursor *cursor,
        char *buf, size_t size_buf, size_t max_chunk)
{
    unsigned str_len = 0;
    struct string_buffer string_buf;
    if (buf) string_buffer_ctor(&string_buf, buf, size_buf);
    do {
        if (cursor->cap_len < 1) break;
        str_len = cursor_read_u8(cursor);
        SLOG(LOG_DEBUG, "Chunk of size of %u", str_len);
        size_t available_bytes = MIN(cursor->cap_len, str_len);
        if (buf) buffer_append_stringn(&string_buf, (char const *)cursor->head, available_bytes);
        cursor_drop(cursor, available_bytes);
    } while (str_len >= max_chunk);
    // There seems to be an null terminator when string length is > 0x40
    // However, it can be a flag after the string. Ignore it for now.
    if (buf) buffer_get_string(&string_buf);
    return PROTO_OK;
}

/* Read an int prefixed by 1 byte size
 * | Size | Int------ |
 * | 0x02 | 0x01 0xdd |
 */
static enum proto_parse_status cursor_read_variable_int(struct cursor *cursor, uint_least64_t *res)
{
    CHECK(1);
    unsigned len = cursor_read_u8(cursor);
    SLOG(LOG_DEBUG, "Variable len has size %d", len);
    return cursor_read_fixed_int_n(cursor, res, len);
}

/* Read a splitted string prefixed by a global variable size
 * Each chunk of string is prefixed by it's size
 * | Size of Size | Size  Size  String---  Size  String---
 * |         0x01 | 0x04  0x02  0x40 0x41  0x02  0x50 0x51
 */
static enum proto_parse_status cursor_read_chunked_string_with_size(struct cursor *cursor, char *buf, size_t buf_size, size_t max_chunk)
{
    uint_least64_t size;
    enum proto_parse_status status;
    status = cursor_read_variable_int(cursor, &size);
    if (status != PROTO_OK) return status;
    if (size > 0) status = cursor_read_chunked_string(cursor, buf, buf_size, max_chunk);
    return status;
}

static bool is_print(char c)
{
    return (c != MAX_OCI_CHUNK) && (isprint(c) || c == '\n' || c == '\r');
}

static bool is_delim(char c)
{
    return c == ')' || c == '\0'; // what else?
}

static void copy_token(char *dst, size_t dst_len, char const *src, size_t src_len)
{
    assert(dst_len > 0);
    while (src_len > 0 && dst_len > 1 && !is_delim(*src)) {
        *dst++ = *src++;
        dst_len --;
        src_len --;
    }
    *dst = '\0';
}

static enum proto_parse_status tns_parse_connect(struct tns_parser unused_ *tns_parser, struct sql_proto_info *info, struct cursor *cursor)
{
    if (! info->is_query) return PROTO_PARSE_ERR;
    SLOG(LOG_DEBUG, "Parsing TNS connect PDU of size %zu", cursor->cap_len);

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
    size_t const pdu_len = cursor->cap_len;
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

static enum proto_parse_status tns_parse_accept(struct tns_parser unused_ *tns_parser, struct sql_proto_info *info, struct cursor *cursor)
{
    if (info->is_query) return PROTO_PARSE_ERR;
    SLOG(LOG_DEBUG, "Parsing TNS accept PDU of size %zu", cursor->cap_len);

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
    CHECK(10);
    unsigned version = cursor_read_u16n(cursor);
    info->version_maj = version/100;
    info->version_min = version%100;
    info->set_values |= SQL_VERSION;
    sql_set_request_status(info, SQL_REQUEST_COMPLETE);
    return PROTO_OK;
}

static enum proto_parse_status tns_parse_row_recap(struct cursor *cursor)
{
    enum proto_parse_status status;
    SLOG(LOG_DEBUG, "Parsing Row recap");

    /* A row recap contains :
     * - 1 var number of column sent
     * - <number of fields> bytes to ignore
     */
    uint_least64_t num_fields;
    status = cursor_read_variable_int(cursor, &num_fields);
    if (status != PROTO_OK) return status;
    unsigned nb_ignore = (num_fields + 7) / 8;
    DROP_FIX(cursor, nb_ignore);
    return PROTO_OK;
}

static enum proto_parse_status read_field_count(struct tns_parser *tns_parser,
        struct sql_proto_info *info, struct cursor *cursor)
{
    enum proto_parse_status status;
    uint_least64_t num_fields;
    if (PROTO_OK != (status = cursor_read_variable_int(cursor, &num_fields))) return status;
    sql_set_field_count(info, num_fields);
    tns_parser->nb_fields = info->u.query.nb_fields;
    SLOG(LOG_DEBUG, "Got %d fields", info->u.query.nb_fields);
    return PROTO_OK;
}

/*
 * | 1 byte | 1 + 0-8 bytes | up to 5 vars |
 * | Flag   | Number column | unknown      |
 */
static enum proto_parse_status tns_parse_row_prefix(struct tns_parser *tns_parser,
        struct sql_proto_info *info, struct cursor *cursor)
{
    enum proto_parse_status status;
    SLOG(LOG_DEBUG, "Parsing Row prefix");

    DROP_FIX(cursor, 1);
    if (PROTO_OK != (status = read_field_count(tns_parser, info, cursor))) return status;
    for (unsigned i = 0; i < 5; i++) {
        CHECK(1);
        char c = cursor_peek_u8(cursor, 0);
        if (c == TTC_ROW_DATA || c == TTC_END_MESSAGE) return PROTO_OK;
        DROP_VAR(cursor);
    }
    return PROTO_OK;
}

static enum proto_parse_status tns_parse_row_data(struct tns_parser *tns_parser, struct sql_proto_info *info, struct cursor *cursor)
{
    enum proto_parse_status status;
    SLOG(LOG_DEBUG, "Parsing row data with %u fields", tns_parser->nb_fields);

    /* A row data contains :
     * - 1 var for each fields
     */
    DROP_VAR_STRS(cursor, tns_parser->nb_fields);
    // Our nb fields might be incorrect
    CHECK(1);
    char c = cursor_peek_u8(cursor, 0);
    if (TTC_END_MESSAGE != c && TTC_ROW_RECAP != c) {
        DROP_VAR_STR(cursor);
        tns_parser->nb_fields++;
    }
    sql_set_field_count(info, tns_parser->nb_fields);
    return PROTO_OK;
}

/*
 * After a query, server sends a list of column name with their types
 *
 * | 1 byte | 1 byte                | 0-8 bytes     | variable bytes           |
 * | Length | Size number of fields | Number fields | unknown flags and fields |
 */
static enum proto_parse_status tns_parse_row_description_prefix(struct tns_parser *tns_parser, struct sql_proto_info *info, struct cursor *cursor)
{
    enum proto_parse_status status;
    SLOG(LOG_DEBUG, "Parsing row description prefix");

    CHECK(1);
    unsigned length = cursor_read_u8(cursor);
    DROP_FIX(cursor, length);
    DROP_VAR(cursor);

    if (PROTO_OK != (status = read_field_count(tns_parser, info, cursor))) return status;

    DROP_FIX(cursor, 1);
    for (unsigned i = 0; i < info->u.query.nb_fields; i++) {
        DROP_FIX(cursor, 3);
        DROP_VARS(cursor, 4);
        DROP_DALC(cursor);
        DROP_VARS(cursor, 2);
        DROP_FIX(cursor, 1);
        DROP_VAR(cursor);
        DROP_FIX(cursor, 2);
        for (unsigned i = 0; i < 3; ++i) {
            DROP_DALC(cursor);
        }
        DROP_VAR(cursor);
    }
    DROP_DALC(cursor);
    DROP_VARS(cursor, 2);
    return PROTO_OK;
}

/*
 * | 1 byte | (length + 1) * variable | 1 + 0-8 bytes | nb_ignore * variable | Variable until new ttc |
 * | length | ?                       | Nb ignore     | ?                    | ?                      |
 */
static enum proto_parse_status tns_parse_row_description(struct cursor *cursor)
{
    enum proto_parse_status status;
    SLOG(LOG_DEBUG, "Parsing a row description");

    uint_least64_t length;
    status = cursor_read_variable_int(cursor, &length);
    if (status != PROTO_OK) return status;
    DROP_VARS(cursor, length);
    DROP_VAR(cursor);

    uint_least64_t nb_ignore;
    status = cursor_read_variable_int(cursor, &nb_ignore);
    if (status != PROTO_OK) return status;
    for (unsigned i = 0; i < nb_ignore; i++) {
        DROP_VAR(cursor);
        DROP_DALC(cursor);
        DROP_VAR(cursor);
    }
    CHECK(1);
    // Sometimes, we have some strange bytes...
    while (*cursor->head < 0x03 || *cursor->head > 0x15) {
        CHECK(2);
        DROP_FIX(cursor, 1);
    }
    return PROTO_OK;
}

static enum proto_parse_status tns_parse_close_statement(struct cursor *cursor)
{
    SLOG(LOG_DEBUG, "Parsing a close statement");
    // Subcode
    DROP_FIX(cursor, 1);
    // Sequence
    DROP_FIX(cursor, 1);
    // Pointer
    DROP_FIX(cursor, 1);

    // We seek the next query
    uint8_t marker[2] = {0x03, 0x5e};
    if (cursor_drop_until(cursor, marker, sizeof(marker), cursor->cap_len) < 0) return PROTO_PARSE_ERR;

    SLOG(LOG_DEBUG, "Found a possible query ttc, exiting close statement");
    return PROTO_OK;
}

static enum sql_msg_type ttc_to_msg_type(struct tns_parser *tns_parser, enum ttc_code ttc_code)
{
    switch (ttc_code) {
        case TTC_DEADBEEF:
        case TTC_LOGIN_PROPERTY:
            return SQL_STARTUP;
        case TTC_DATA_REPRESENTATION:
        case TTC_QUERY:
        case TTC_ROW_PREFIX:
        case TTC_ROW_DATA:
        case TTC_ROW_DESCRIPTION:
        case TTC_ROW_DESCRIPTION_PREFIX:
        case TTC_CLOSE:
        case TTC_ROW_RECAP:
            return SQL_QUERY;
        case TTC_END_MESSAGE:
            return tns_parser->msg_type == SQL_QUERY ? SQL_QUERY : SQL_STARTUP;
        default:
            return SQL_UNKNOWN;
    }
}

static enum proto_parse_status tns_parse_end(struct sql_proto_info *info, struct cursor *cursor)
{
    SLOG(LOG_DEBUG, "Parsing tns end packet");
    enum proto_parse_status status;

    uint_least64_t var[6];
    for (unsigned i = 0; i < 6; i++) {
        if (PROTO_OK != (status = cursor_read_variable_int(cursor, var + i))) return status;
    }

    uint_least64_t nb_rows;
    uint_least64_t error_code;

    // let's use the double 0x00 to guess the position of row number and error code
    if (var[0] > 0 && var[4] == 0 && var[5] == 0) {
        // var[0] is unknown?
        // var[1] == sequence
        // var[2] == rows
        // var[3] == error code
        SLOG(LOG_DEBUG, "Unknown bits after ttc code");
        nb_rows = var[2];
        error_code = var[3];
        DROP_VAR(cursor);
    } else if (var[3] == 0 && var[4] == 0) {
        // var[0] == sequence
        // var[1] == rows
        // var[2] == error code
        nb_rows = var[1];
        error_code = var[2];
    } else {
        // var[0] == rows
        // var[1] == error code
        nb_rows = var[0];
        error_code = var[1];
    }

    if (info->msg_type == SQL_QUERY) {
        sql_set_row_count(info, nb_rows);
        SLOG(LOG_DEBUG, "Nb rows %d", info->u.query.nb_rows);
    }
    SLOG(LOG_DEBUG, "Error code is %zu", error_code);

    DROP_VARS(cursor, 1);
    DROP_FIX(cursor, 2);
    DROP_VARS(cursor, 2);
    DROP_FIX(cursor, 2);
    DROP_VARS(cursor, 2);
    DROP_FIX(cursor, 1);
    DROP_VARS(cursor, 3);

    if (error_code != 0) {
        SLOG(LOG_DEBUG, "Parsing error message");
        char *error_msg = tempstr();
        unsigned error_len;

        // Drop an unknown number of bytes here
        while(cursor->cap_len > 2 && (cursor_peek_u8(cursor, 0) == 0 || !is_print(cursor_peek_u8(cursor, 1)))){
            DROP_FIX(cursor, 1);
        }
        SLOG(LOG_DEBUG, "First printable char is %c", cursor_peek_u8(cursor, 1));
        status = cursor_read_variable_string(cursor, error_msg, TEMPSTR_SIZE, &error_len);
        if (status != PROTO_OK) return status;
        if (error_len < 12) return PROTO_PARSE_ERR;
        // Split "ORA-XXXX: msg"
        // Part before : is the error code
        // Part after is the localized message
        char *colon_pos = memchr(error_msg, ':', error_len);
        sql_set_request_status(info, SQL_REQUEST_ERROR);
        if (colon_pos) {
            // We extract the error code
            unsigned error_code_size = colon_pos - error_msg;
            int size_err = MIN(error_code_size, sizeof(info->error_code));
            memcpy(info->error_code, error_msg, size_err);
            info->error_code[size_err] = '\0';
            info->set_values |= SQL_ERROR_CODE;
            if (0 == strcmp("ORA-01403", info->error_code))
                info->request_status = SQL_REQUEST_COMPLETE;

            // We skip ':' in errror message
            char const *start_message = colon_pos + 1;
            // We skip spaces before errror message
            while (start_message < error_len + error_msg && *start_message == ' ')
                start_message++;

            copy_string(info->error_message, start_message, sizeof(info->error_message));
            info->set_values |= SQL_ERROR_MESSAGE;
        } else {
            copy_string(info->error_message, error_msg, sizeof(info->error_message));
            info->set_values |= SQL_ERROR_MESSAGE;
        }
    }

    return PROTO_OK;
}

static enum proto_parse_status is_range_print(struct cursor *cursor, size_t size, size_t offset)
{
    CHECK(size + offset);
    SLOG(LOG_DEBUG, "Check range print with size %zu, and offset %zu", size, offset);
    for (size_t i = 0; i < size; i++) {
        if (!is_print(cursor_peek_u8(cursor, i + offset)))
            return PROTO_PARSE_ERR;
    }
    return PROTO_OK;
}

#define MIN_QUERY_SIZE 10
#define QUERY_WITH_SIZE 12
static bool is_query_valid(struct cursor *cursor, uint8_t potential_size)
{
    if (cursor->cap_len <= QUERY_WITH_SIZE) return false;
    // We check if last character is printable
    uint8_t left_size = potential_size - 1; // Since we already read the first char
    uint8_t last_char_pos = MIN(cursor->cap_len, left_size) - 1;
    uint8_t last_char = cursor_peek_u8(cursor, last_char_pos);
    if (!is_print(last_char)) {
        SLOG(LOG_DEBUG, "Last char 0x%02x is not printable", last_char);
        return false;
    }
    // We check if last character + 1 is not printable. If it is printable, size might be incorrect
    // We assume chunked string if size >= 0x40
    if (potential_size < MAX_OCI_CHUNK && (potential_size < cursor->cap_len)) {
        char next_char = cursor_peek_u8(cursor, left_size);
        if (is_print(next_char)) {
            SLOG(LOG_DEBUG, "Char following last char 0x%02x is printable", next_char);
            return false;
        }
    }
    // We check if first characters are printable
    if (PROTO_OK == is_range_print(cursor, MIN_QUERY_SIZE, 0)) {
        return true;
    }
    return false;
}

/*
 *  Sometimes, we have 10 {0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff} patterns. Skip them to avoid
 *  breaking on an eventual 0x07 (TTC_ROW_DATA)
 *  The query size seems to be at the end of the first pattern
 */
static uint8_t parse_query_header(struct cursor *cursor)
{
    uint8_t const *new_head = cursor->head;
    uint8_t sql_size = 0;
    for (unsigned i = 0; i < 10 && new_head; i++) {
        char pattern[8] = {0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        new_head = memmem(cursor->head, cursor->cap_len, pattern, sizeof(pattern));
        if (new_head) {
            size_t gap_size = new_head - cursor->head;
            DROP_FIX(cursor, gap_size + sizeof(pattern));
            if (i == 0) {
                CHECK(1);
                sql_size = cursor_read_u8(cursor);
                SLOG(LOG_DEBUG, "Found potential sql size: %d", sql_size);
            }
        }
    };
    return sql_size;
}

/*
 * Check if query is valid.
 * @param cursor to read
 * @param is_chunked Filled to true if string is preceded by size
 * @param sql_size Potential sql size parsed in query headers
 * @return True if a correct query has been found and cursor is positioned at the begin of the query
 */
static bool lookup_query(struct cursor *cursor, bool *is_chunked, uint8_t sql_size)
{
    SLOG(LOG_DEBUG, "Start looking for query");
    uint8_t prec = 0;
    uint8_t current = 0;
    while (cursor->cap_len > QUERY_WITH_SIZE) {
        prec = current;
        current = cursor_read_u8(cursor);
        if (current == TTC_ROW_DATA) {
            SLOG(LOG_DEBUG, "Looks like a data row, we found no matching query...");
            return false;
        }
        if (!is_print(current)) continue;
        SLOG(LOG_DEBUG, "Found potential first printable %c, previous 0x%02x", current, prec);
        if (prec > MIN_QUERY_SIZE && is_query_valid(cursor, prec)) {
            SLOG(LOG_DEBUG, "Found potential size 0x%02x and first printable %c", prec, current);
            cursor_rollback(cursor, 2);
            *is_chunked = true;
            return true;
        }
        if (sql_size > MIN_QUERY_SIZE && current != sql_size && is_query_valid(cursor, sql_size)) {
            SLOG(LOG_DEBUG, "Found query with sql size 0x%02x and first printable %c", sql_size, current);
            cursor_rollback(cursor, 1);
            *is_chunked = false;
            return true;
        }
    }
    return false;
}

static enum proto_parse_status tns_parse_sql_query_oci(struct sql_proto_info *info, struct cursor *cursor)
{
    SLOG(LOG_DEBUG, "Parsing an oci query");
    uint8_t sql_size = parse_query_header(cursor);
    bool is_chunked;
    bool has_query = lookup_query(cursor, &is_chunked, sql_size);
    info->u.query.sql[0] = '\0';
    info->u.query.truncated = 0;
    if (has_query) {
        SLOG(LOG_DEBUG, "Found a query, parsing it");
        if (is_chunked) cursor_read_chunked_string(cursor, info->u.query.sql, sizeof(info->u.query.sql), MAX_OCI_CHUNK);
        else cursor_read_fixed_string(cursor, info->u.query.sql, sizeof(info->u.query.sql), sql_size);
    }
    SLOG(LOG_DEBUG, "Sql parsed: %s", info->u.query.sql);
    info->set_values |= SQL_SQL;
    // Drop the rest
    if(cursor->cap_len > 0) cursor_drop(cursor, cursor->cap_len - 1);

    return PROTO_OK;
}

/*
 * | 1 byte | 1 + 0-8 bytes | 1 byte | 1 + 0-4 bytes  | Lots of unknown bytes | variable  |
 * | Unk    | Sql len       | Unk    | Num end fields | Unk                   | sql query |
 */
static enum proto_parse_status tns_parse_sql_query_jdbc(struct sql_proto_info *info, struct cursor *cursor)
{
    SLOG(LOG_DEBUG, "Parsing a jdbc query");
    enum proto_parse_status status = PROTO_OK;

    DROP_FIX(cursor, 1);

    uint_least64_t sql_len;
    if (PROTO_OK != (status = cursor_read_variable_int(cursor, &sql_len))) return status;
    SLOG(LOG_DEBUG, "Size sql %zu", sql_len);

    DROP_FIX(cursor, 1);
    DROP_VAR(cursor);
    DROP_FIX(cursor, 2);

    info->u.query.sql[0] = '\0';
    info->u.query.truncated = 0; // TODO Handle truncated
    if (sql_len > 0) {
        // Some unknown bytes
        while (cursor->cap_len > 1 && PROTO_OK != is_range_print(cursor, MIN(MIN_QUERY_SIZE, sql_len), 1)) {
            // TODO drop to the first non printable
            cursor_drop(cursor, 1);
        }
        CHECK(1);
        if (sql_len > 0xff && 0xff == cursor_peek_u8(cursor, 0)) {
            SLOG(LOG_DEBUG, "Looks like prefixed length chunks of size 0xff...");
            status = cursor_read_chunked_string(cursor, info->u.query.sql, sizeof(info->u.query.sql), 0xff);
        } else if (sql_len > MAX_OCI_CHUNK && MAX_OCI_CHUNK == cursor_peek_u8(cursor, 0)) {
            SLOG(LOG_DEBUG, "Looks like prefixed length chunks of size 0x40...");
            status = cursor_read_chunked_string(cursor, info->u.query.sql, sizeof(info->u.query.sql), MAX_OCI_CHUNK);
        } else {
            // We don't care about the first non printable character
            cursor_drop(cursor, 1);
            CHECK(1);
            // In rare occurrence where sql_len == first character, we check the byte after the expected query,
            // if it's printable, the first character is probably the prefixed size.
            if (cursor_peek_u8(cursor, 0) == sql_len && sql_len < cursor->cap_len && is_print(cursor_peek_u8(cursor, sql_len)))
                cursor_drop(cursor, 1);
            SLOG(LOG_DEBUG, "Looks like a fixed string of size %zu", sql_len);
            int written_bytes = cursor_read_fixed_string(cursor, info->u.query.sql,
                    sizeof(info->u.query.sql), sql_len);
            if (written_bytes < 0) return PROTO_TOO_SHORT;
        }
        if (status != PROTO_OK) return status;
    }
    SLOG(LOG_DEBUG, "Sql parsed: %s", info->u.query.sql);
    info->set_values |= SQL_SQL;

    return PROTO_OK;
}

/*
 * If oci, we will fallback on start query guesstimation
 * | 1 byte                        |
 * | Some flags (generally > 0x04) |
 *
 * If jdbc:
 * | 1 byte      | 0-4 bytes | 1 byte   | 0-4 bytes |
 * | Option size | Options   | Var size | Var value |
 */
static bool is_oci(struct cursor *cursor)
{
    CHECK(1);
    unsigned option_size = cursor_read_u8(cursor);
    CHECK(MAX(option_size, 2));
    if (option_size > 0x04 || cursor_peek_u8(cursor, 1) == 0x00) return true;
    cursor_drop(cursor, option_size);

    // Should be a var here
    CHECK(1);
    unsigned var_size = cursor_read_u8(cursor);
    CHECK(MAX(var_size, 2));
    if (var_size > 0x04 || cursor_peek_u8(cursor, 1) == 0x00) return true;
    cursor_drop(cursor, var_size);

    return false;
}

static enum proto_parse_status tns_parse_sql_query(struct sql_proto_info *info, struct cursor *cursor)
{
    DROP_FIX(cursor, 1);
    if (is_oci(cursor)) {
        // Option is not prefix based, seems like an oci query
        return tns_parse_sql_query_oci(info, cursor);
    } else {
        struct cursor save_cursor = *cursor;
        if (tns_parse_sql_query_jdbc(info, cursor) != PROTO_OK) {
            // Fallback to query guessing
            SLOG(LOG_DEBUG, "jdbc query failed, fallback to oci");
            *cursor = save_cursor;
            return tns_parse_sql_query_oci(info, cursor);
        } else {
            return PROTO_OK;
        }
    }
}

static enum proto_parse_status tns_parse_query(struct tns_parser *tns_parser, struct sql_proto_info *info, struct cursor *cursor)
{
    enum proto_parse_status status = PROTO_OK;
    CHECK(1);
    enum query_subcode query_subcode = cursor_read_u8(cursor);
    SLOG(LOG_DEBUG, "Parsing tns query, subcode is %u", query_subcode);
    switch (query_subcode) {
        case TTC_QUERY_SQL:
        case TTC_QUERY_ALL_7:
            tns_parser->nb_fields = UNSET;
            status = tns_parse_sql_query(info, cursor);
            break;
        case TTC_QUERY_FETCH:
            break;
        default:
            // Probably initialization queries. Since we are unsure, don't
            // return PROTO_OK to avoid fix of c2s_way
            return PROTO_PARSE_ERR;
    }
    cursor_drop(cursor, cursor->cap_len);
    return status;
}

static enum proto_parse_status tns_parse_login_property(struct sql_proto_info *info, struct cursor *cursor)
{
    SLOG(LOG_DEBUG, "Parsing tns login property");
    // We are only interested in response
    if (info->is_query) return PROTO_OK;
    if (info->msg_type != SQL_UNKNOWN && info->msg_type != SQL_STARTUP) return PROTO_PARSE_ERR;

    // Drop Server version
    DROP_FIX(cursor, 3);
    // Drop Server version text
    uint8_t marker = 0x00;
    if (cursor_drop_until(cursor, &marker, sizeof(marker), cursor->cap_len) < 0) return PROTO_PARSE_ERR;
    // Drop Null byte
    DROP_FIX(cursor, 1);
    CHECK(2);
    uint16_t charset = cursor_read_u16le(cursor);
    SLOG(LOG_DEBUG, "Found a charset of 0x%02x", charset);
    switch (charset) {
        case 0x01:
        case 0x02:
        case 0x1f:
        case 0xb2:
            sql_set_encoding(info, SQL_ENCODING_LATIN1);
            break;
        case 0x366:
        case 0x367:
        case 0x369:
            sql_set_encoding(info, SQL_ENCODING_UTF8);
            break;
        default:
            SLOG(LOG_DEBUG, "Unknown charset");
            break;
    }
    // We don't care of the rest...
    cursor_drop(cursor, cursor->cap_len);
    return PROTO_OK;
}

/*
 * | 2 bytes | 1 byte   | Variable |
 * | Flags   | TTC code | TTC body |
 */
static enum proto_parse_status tns_parse_data(struct tns_parser *tns_parser, struct sql_proto_info *info, struct cursor *cursor,
        unsigned way)
{
    SLOG(LOG_DEBUG, "Parsing TNS data PDU of size %zu", cursor->cap_len);
    enum proto_parse_status status = PROTO_OK;

    // First, read the data flags
    CHECK(2);
    unsigned flags = cursor_read_u16n(cursor);
    SLOG(LOG_DEBUG, "Data flags = 0x%x", flags);
    if (flags & 0x40) { // End Of File
        if (cursor->cap_len != 0) return PROTO_PARSE_ERR;   // This may be wrong, maybe a command is allowed anyway
        info->msg_type = SQL_EXIT;
        sql_set_request_status(info, SQL_REQUEST_COMPLETE);
        return PROTO_OK;
    }
    info->msg_type = tns_parser->msg_type;
    while (status == PROTO_OK && cursor->cap_len) {
        CHECK(1);
        enum ttc_code ttc_code = cursor_read_u8(cursor);
        SLOG(LOG_DEBUG, "Ttc code = 0x%02x, msg type %s", ttc_code, sql_msg_type_2_str(tns_parser->msg_type));
        switch (ttc_code) {
            case TTC_ROW_PREFIX:
                status = tns_parse_row_prefix(tns_parser, info, cursor);
                break;
            case TTC_ROW_DATA:
                status = tns_parse_row_data(tns_parser, info, cursor);
                break;
            case TTC_ROW_DESCRIPTION_PREFIX:
                status = tns_parse_row_description_prefix(tns_parser, info, cursor);
                break;
            case TTC_ROW_RECAP:
                status = tns_parse_row_recap(cursor);
                break;
            case TTC_ROW_DESCRIPTION:
                status = tns_parse_row_description(cursor);
                break;
            case TTC_LOGIN_PROPERTY:
                status = tns_parse_login_property(info, cursor);
                break;
            case TTC_QUERY:
                status = tns_parse_query(tns_parser, info, cursor);
                break;
            case TTC_END_MESSAGE:
                status = tns_parse_end(info, cursor);
                break;
            case TTC_CLOSE:
                status = tns_parse_close_statement(cursor);
                break;
            default:
                SLOG(LOG_DEBUG, "Unknown ttc_code = %u", ttc_code);
                return PROTO_OK;
        }
        if (status == PROTO_OK) {
            enum sql_msg_type ttc_msg_type = ttc_to_msg_type(tns_parser, ttc_code);
            if (ttc_msg_type != SQL_UNKNOWN) {
                info->msg_type = ttc_msg_type;
                tns_parser->msg_type = ttc_msg_type;
            }
            // Fix c2s_way
            bool old_c2s_way = tns_parser->c2s_way;
            switch (ttc_code) {
                case TTC_ROW_DESCRIPTION_PREFIX:
                case TTC_ROW_RECAP:
                case TTC_ROW_DESCRIPTION:
                case TTC_END_MESSAGE:
                    tns_parser->c2s_way = !way;
                    break;
                case TTC_QUERY:
                case TTC_CLOSE:
                    tns_parser->c2s_way = way;
                    break;
                default:
                    break;
            }
            if (old_c2s_way != tns_parser->c2s_way) {
                SLOG(LOG_DEBUG, "Fix c2s way from %d to %d", old_c2s_way, tns_parser->c2s_way);
            }
            info->is_query = way == tns_parser->c2s_way;
        }
    }
    return status;
}

static enum proto_parse_status tns_sbuf_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct tns_parser *tns_parser = DOWNCAST(parser, parser, tns_parser);

    // If this is the first time we are called, init c2s_way
    if (tns_parser->c2s_way == UNSET) {
        ASSIGN_INFO_OPT(tcp, parent);
        if (tcp) tns_parser->c2s_way = tcp->to_srv ? way : !way;
        else tns_parser->c2s_way = way;
        SLOG(LOG_DEBUG, "First packet, init c2s_way to %u", tns_parser->c2s_way);
    }

    if (!timeval_is_set(&tns_parser->first_ts)) {
        SLOG(LOG_DEBUG, "Setting first ts to %s", timeval_2_str(now));
        tns_parser->first_ts = *now;
    }

    // Now build the proto_info
    struct sql_proto_info info;
    SLOG(LOG_DEBUG, "Constructing with %zu", wire_len);
    proto_info_ctor(&info.info, parser, parent, wire_len, 0);
    info.is_query = way == tns_parser->c2s_way;
    info.set_values = 0;
    info.msg_type = SQL_UNKNOWN;
    info.first_ts = tns_parser->first_ts;

    // and try to read a TNS PDN
    struct cursor cursor;
    cursor_ctor(&cursor, payload, cap_len);

    uint8_t const *const msg_start = cursor.head;
    size_t pdu_len = 0;
    enum tns_type pdu_type = 0;
    enum proto_parse_status status = cursor_read_tns_hdr(&cursor, &pdu_len, &pdu_type, wire_len);
    if (status == PROTO_PARSE_ERR) {
        SLOG(LOG_DEBUG, "Error while parsing tns header");
        timeval_reset(&tns_parser->first_ts);
        return status;
    }

    bool has_gap = cap_len < wire_len;
    if (status == PROTO_TOO_SHORT && !has_gap) {
        proto_parse(NULL, parent, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
        streambuf_set_restart(&tns_parser->sbuf, way, msg_start, pdu_len > 0 ? pdu_len : 8);
        SLOG(LOG_DEBUG, "Payload too short for parsing message, will restart @ %zu", tns_parser->sbuf.dir->restart_offset);
        return PROTO_OK;
    }
    switch (pdu_type) {
        case TNS_CONNECT:
            info.msg_type = SQL_STARTUP;
            status = tns_parse_connect(tns_parser, &info, &cursor);
            break;
        case TNS_ACCEPT:
            info.msg_type = SQL_STARTUP;
            status = tns_parse_accept(tns_parser, &info, &cursor);
            break;
        case TNS_DATA:
            status = tns_parse_data(tns_parser, &info, &cursor, way);
            break;
        case TNS_RESEND:
            SLOG(LOG_DEBUG, "Got a tns resend");
            break;
        case TNS_REFUSE:
        case TNS_REDIRECT:
        case TNS_ABORT:
        case TNS_MARKER:
        case TNS_ATTENTION:
        case TNS_CONTROL:
        default:    // A type we do not handle, skip the PDU
            break;
    }

    // We advertize the tns pdu even if we don't know how to parse it
    if (status != PROTO_OK) SLOG(LOG_DEBUG, "Error parsing tns packet");
    timeval_reset(&tns_parser->first_ts);
    return proto_parse(NULL, &info.info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
}

static enum proto_parse_status tns_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct tns_parser *tns_parser = DOWNCAST(parser, parser, tns_parser);

    enum proto_parse_status const status = streambuf_add(&tns_parser->sbuf, parser, parent, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);

    return status;
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
        .parse       = tns_parse,
        .parser_new  = tns_parser_new,
        .parser_del  = tns_parser_del,
        .info_2_str  = sql_info_2_str,
        .info_addr   = sql_info_addr
    };
    proto_ctor(&proto_tns_, &ops, "TNS", PROTO_CODE_TNS);
    port_muxer_ctor(&tns_tcp_muxer, &tcp_port_muxers, 1521, 1521, proto_tns);
}

void tns_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    port_muxer_dtor(&tns_tcp_muxer, &tcp_port_muxers);
    proto_dtor(&proto_tns_);
#   endif
    log_category_proto_tns_fini();
}

