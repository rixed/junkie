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
    TNS_TYPE_MAX  = 19
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
    TTC_QUERY_SQL           = 0x5e,
    TTC_CLOSE_STATEMENT     = 0x69,
};

struct tns_parser {
    struct parser parser;
    unsigned c2s_way;   // The way when traffic is going from client to server (UNSET for unset)
    struct streambuf sbuf;
    unsigned nb_fields; // Keep number of fields for query response
    enum sql_msg_type msg_type;
};

static parse_fun tns_sbuf_parse;

static int tns_parser_ctor(struct tns_parser *tns_parser, struct proto *proto)
{
    assert(proto == proto_tns);
    if (0 != parser_ctor(&tns_parser->parser, proto)) return -1;
    tns_parser->c2s_way = UNSET;    // unset
    tns_parser->nb_fields = UNSET;
    tns_parser->msg_type = SQL_UNKNOWN;
    if (0 != streambuf_ctor(&tns_parser->sbuf, tns_sbuf_parse, 30000)) return -1;

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
    if ((status = cursor_read_variable_string(cursor, NULL, NULL) != PROTO_OK))     \
        return status;

#define DROP_VAR_STRS(cursor, count)                                                \
    for (unsigned x = 0; x < count; x++) {                                          \
        if ((status = cursor_read_variable_string(cursor, NULL, NULL) != PROTO_OK)) \
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
    if ((status = cursor_read_chunked_string_with_size(cursor, NULL, MAX_OCI_CHUNK) != PROTO_OK)) \
        return status;

static enum proto_parse_status cursor_read_tns_hdr(struct cursor *cursor, size_t *out_len, unsigned *out_type)
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
    SLOG(LOG_DEBUG, "TNS PDU len == %zu", len);
    // skip packet checksum (2 bytes)
    cursor_drop(cursor, 2);
    unsigned type = cursor_read_u8(cursor);
    // Skip Reserved byte and header checksum (1 + 2 bytes)
    cursor_drop(cursor, 3);
    if (type > TNS_TYPE_MAX) return PROTO_PARSE_ERR;

    // Check we have the msg payload
    CHECK_LEN(cursor, len, 8);

    if (out_len) *out_len = len;
    if (out_type) *out_type = type;
    return PROTO_OK;
}

static enum proto_parse_status cursor_drop_until(struct cursor *cursor, const void *marker, size_t marker_len)
{
    uint8_t *new_head = memmem(cursor->head, cursor->cap_len, marker, marker_len);
    if (!new_head) return PROTO_PARSE_ERR;
    size_t gap_size = new_head - cursor->head;
    cursor_drop(cursor, gap_size);
    return PROTO_OK;
}

/* Read a string prefixed by 1 byte size
 * Size  String-------------
 * 0x04  0x41 0x42 0x42 0x40
 */
static enum proto_parse_status cursor_read_variable_string(struct cursor *cursor, char **out_str, unsigned *out_str_len)
{
    unsigned str_len;
    CHECK(1);
    str_len = cursor_read_u8(cursor);
    SLOG(LOG_DEBUG, "Reading variable str of length %d", str_len);
    if (out_str_len) *out_str_len = str_len;
    return cursor_read_fixed_string(cursor, out_str, str_len);
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
static enum proto_parse_status cursor_read_chunked_string(struct cursor *cursor, char **out_str, size_t max_chunk)
{
    char *str = tempstr();
    unsigned pos = 0;
    while (pos < TEMPSTR_SIZE) {
        CHECK(1);
        unsigned str_len = cursor_read_u8(cursor);
        SLOG(LOG_DEBUG, "Chunk of size of %u", str_len);

        CHECK(str_len);
        size_t copied_len = MIN(TEMPSTR_SIZE - (pos + str_len + 1), str_len);
        cursor_copy(str + pos, cursor, copied_len);
        pos += str_len;
        if (str_len < max_chunk) break;
    }
    // There seems to be an null terminator when string length is > 0x40
    // However, it can be a flag after the string. Ignore it for now.
    if (out_str) *out_str = str;
    str[MIN(pos, TEMPSTR_SIZE)] = 0;
    SLOG(LOG_DEBUG, "Chunk parsed of size %u", pos);
    return PROTO_OK;
}

/* Read an int prefixed by 1 byte size
 * Size  Int------
 * 0x02  0x01 0xdd
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
 * Size of Size  Size  Size  String---  Size  String---
 *         0x01  0x04  0x02  0x40 0x41  0x02  0x50 0x51
 */
static enum proto_parse_status cursor_read_chunked_string_with_size(struct cursor *cursor, char **res, size_t max_chunk)
{
    uint_least64_t size;
    enum proto_parse_status status;
    status = cursor_read_variable_int(cursor, &size);
    if (status != PROTO_OK) return status;
    if (size > 0) {
        status = cursor_read_chunked_string(cursor, res, max_chunk);
    }
    return status;
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

static enum proto_parse_status tns_parse_row_prefix(struct tns_parser *tns_parser,
        struct sql_proto_info *info, struct cursor *cursor)
{
    enum proto_parse_status status;
    SLOG(LOG_DEBUG, "Parsing Row prefix");

    /* A row prefix contains
     * - 1 byte flag
     * - Number column
     * - 5 var
     */
    DROP_FIX(cursor, 1);
    if (PROTO_OK != (status = read_field_count(tns_parser, info, cursor))) return status;
    DROP_VARS(cursor, 5);
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
    // Sometimes, we have some strange bytes...
    while (*cursor->head < 0x03 || *cursor->head > 0x15) {
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
    enum proto_parse_status status = cursor_drop_until(cursor, marker, sizeof(marker));
    if (status != PROTO_OK) return status;

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

    uint_least64_t var0;
    uint_least64_t var1;
    uint_least64_t var2;
    uint_least64_t var3;
    uint_least64_t var4;
    uint_least64_t var5;
    if (PROTO_OK != (status = cursor_read_variable_int(cursor, &var0))) return status;
    if (PROTO_OK != (status = cursor_read_variable_int(cursor, &var1))) return status;
    if (PROTO_OK != (status = cursor_read_variable_int(cursor, &var2))) return status;
    if (PROTO_OK != (status = cursor_read_variable_int(cursor, &var3))) return status;
    if (PROTO_OK != (status = cursor_read_variable_int(cursor, &var4))) return status;
    if (PROTO_OK != (status = cursor_read_variable_int(cursor, &var5))) return status;

    uint_least64_t nb_rows;
    uint_least64_t error_code;

    if (var0 != 0 && var4 == 0 && var5 == 0) {
        // First var is unknown?
        SLOG(LOG_DEBUG, "Unknown bits after ttc code");
        nb_rows = var2;
        error_code = var3;
        DROP_VAR(cursor);
    } else {
        // var0 == sequence
        // var1 == rows
        // var2 == error code
        nb_rows = var1;
        error_code = var2;
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
    DROP_FIX(cursor, 2);
    DROP_VARS(cursor, 2);

    if (error_code != 0) {
        SLOG(LOG_DEBUG, "Parsing error message");
        char *error_msg;
        unsigned error_len;

        // Drop an unknown number of column here
        while(cursor->cap_len > 1 && !isprint(*(cursor->head + 1))){
            DROP_FIX(cursor, 1);
        }
        status = cursor_read_variable_string(cursor, &error_msg, &error_len);
        if (status != PROTO_OK) return status;
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

static enum proto_parse_status is_range_print(struct cursor *cursor, size_t size)
{
    CHECK(size);
    for (size_t i = 0; i < size; i++) {
        if (!isprint(cursor_peek_u8(cursor, i)))
            return PROTO_PARSE_ERR;
    }
    return PROTO_OK;
}

static bool lookup_query(struct cursor *cursor)
{
    #define MIN_QUERY_SIZE 10
    #define QUERY_WITH_SIZE 12
    while (cursor->cap_len > QUERY_WITH_SIZE) {
        uint8_t c;
        uint8_t potential_size = 0;
        do {
            c = cursor_peek_u8(cursor, 1);
            potential_size = cursor_read_u8(cursor);
        } while (cursor->cap_len > QUERY_WITH_SIZE && !isprint(c));
        SLOG(LOG_DEBUG, "Found potential size 0x%02x and first printable %c", potential_size, c);
        // Check on found size
        if (potential_size < MIN_QUERY_SIZE || potential_size > cursor->cap_len) continue;
        // We check if last character is printable
        if (!isprint(cursor_peek_u8(cursor, potential_size - 1))) continue;
        // We check if first characters are printable
        if (PROTO_OK == is_range_print(cursor, MIN_QUERY_SIZE)) {
            cursor_rollback(cursor, 1);
            return true;
        }
    }
    return false;
}

static enum proto_parse_status tns_parse_sql_query_oci(struct sql_proto_info *info, struct cursor *cursor)
{
    SLOG(LOG_DEBUG, "Parsing an oci query");
    enum proto_parse_status status;
    char pattern[] = {0xfe, MAX_OCI_CHUNK};
    uint8_t const *new_head = memmem(cursor->head, cursor->cap_len, pattern, sizeof(pattern));
    if (new_head != NULL) {
        size_t gap_size = new_head - cursor->head;
        SLOG(LOG_DEBUG, "%zu bytes before sql", gap_size);
        DROP_FIX(cursor, gap_size + 1);
    } else {
        SLOG(LOG_DEBUG, "{0xfe 0x40} not found, size might be < 0x40");
        if (!lookup_query(cursor)) return PROTO_PARSE_ERR;
    }

    char *sql;
    if (PROTO_OK != (status = cursor_read_chunked_string(cursor, &sql, MAX_OCI_CHUNK))) return status;
    SLOG(LOG_DEBUG, "Sql parsed: %s", sql);
    sql_set_query(info, "%s", sql);

    // Drop the rest
    if(cursor->cap_len > 0) cursor_drop(cursor, cursor->cap_len - 1);

    return PROTO_OK;
}

static enum proto_parse_status tns_parse_sql_query_jdbc(struct sql_proto_info *info, struct cursor *cursor)
{
    SLOG(LOG_DEBUG, "Parsing a jdbc query");
    enum proto_parse_status status;

    DROP_FIX(cursor, 1);

    uint_least64_t sql_len;
    status = cursor_read_variable_int(cursor, &sql_len);
    if (status != PROTO_OK) return status;
    SLOG(LOG_DEBUG, "Size sql %zu", sql_len);

    DROP_FIX(cursor, 1);
    // We have a number of fields at the end of the query
    uint_least64_t end_len;
    status = cursor_read_variable_int(cursor, &end_len);
    if (status != PROTO_OK) return status;

    DROP_FIX(cursor, 2);
    DROP_VARS(cursor, 3);
    DROP_FIX(cursor, 1);
    DROP_VAR(cursor);
    DROP_FIX(cursor, 6);
    DROP_VAR(cursor);

    char *sql = "";
    if (sql_len > 0) {
        // Some unknown bytes
        while (cursor->cap_len > 1 && !isprint(cursor_peek_u8(cursor, 1))) {
            cursor_drop(cursor, 1);
        }

        CHECK(1);
        if (sql_len > 0xff && 0xff == cursor_peek_u8(cursor, 0)) {
            SLOG(LOG_DEBUG, "Looks like prefixed length chunks of size 0xff...");
            status = cursor_read_chunked_string(cursor, &sql, 0xff);
        } else if (sql_len > 0x40 && 0x40 == cursor_peek_u8(cursor, 1)) {
            SLOG(LOG_DEBUG, "Looks like prefixed length chunks of size 0x40...");
            cursor_drop(cursor, 1);
            status = cursor_read_chunked_string(cursor, &sql, 0x40);
        } else {
            if (!isprint(cursor_peek_u8(cursor, 0))) {
                cursor_drop(cursor, 1);
            }
            SLOG(LOG_DEBUG, "Looks like a fixed string of size %zu", sql_len);
            status = cursor_read_fixed_string(cursor, &sql, sql_len);
        }
        if (status != PROTO_OK) return status;
    }
    SLOG(LOG_DEBUG, "Sql parsed: %s", sql);
    sql_set_query(info, "%s", sql);

    SLOG(LOG_DEBUG, "Skipping %zu end variable fields", end_len);
    DROP_VARS(cursor, end_len);
    return PROTO_OK;
}

static bool is_oci(struct cursor *cursor)
{
    CHECK(1);
    unsigned option_size = cursor_read_u8(cursor);
    CHECK(option_size);
    if (option_size > 0x04 || cursor_peek_u8(cursor, 1) == 0x00) return true;
    cursor_drop(cursor, option_size);

    // Should be a var here
    CHECK(1);
    unsigned var_size = cursor_read_u8(cursor);
    CHECK(var_size);
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
        return tns_parse_sql_query_jdbc(info, cursor);
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
            tns_parser->nb_fields = UNSET;
            status = tns_parse_sql_query(info, cursor);
            cursor_drop(cursor, cursor->cap_len);
            break;
        case TTC_QUERY_FETCH:
            cursor_drop(cursor, cursor->cap_len);
            break;
        default:
            // Probably initialization queries
            cursor_drop(cursor, cursor->cap_len);
            break;
    }
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
    enum proto_parse_status status = cursor_drop_until(cursor, &marker, sizeof(marker));
    if (status != PROTO_OK) return status;
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
            switch (ttc_code) {
                case TTC_ROW_DATA:
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

    uint8_t const *const msg_start = cursor.head;
    size_t pdu_len;
    enum tns_type pdu_type;
    enum proto_parse_status status = cursor_read_tns_hdr(&cursor, &pdu_len, &pdu_type);
    if (status == PROTO_PARSE_ERR) return status;
    if (status == PROTO_TOO_SHORT) {
        streambuf_set_restart(&tns_parser->sbuf, way, msg_start, true);
        SLOG(LOG_DEBUG, "Payload too short for parsing message, will restart @ %zu", tns_parser->sbuf.dir->restart_offset);
        return PROTO_OK;
    }
    assert(cursor.cap_len >= pdu_len);  // We have the whole msg ready to be read
    struct cursor msg;
    cursor_ctor(&msg, cursor.head, pdu_len);
    switch (pdu_type) {
        case TNS_CONNECT:
            info.msg_type = SQL_STARTUP;
            status = tns_parse_connect(tns_parser, &info, &msg);
            break;
        case TNS_ACCEPT:
            info.msg_type = SQL_STARTUP;
            status = tns_parse_accept(tns_parser, &info, &msg);
            break;
        case TNS_DATA:
            status = tns_parse_data(tns_parser, &info, &msg, way);
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
