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
#include <inttypes.h>
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

struct tns_parser {
    struct parser parser;
    unsigned c2s_way;   // The way when traffic is going from client to server (UNSET for unset)
    struct streambuf sbuf;
    unsigned nb_fields; // Keep number of fields for query response
};

static parse_fun tns_sbuf_parse;

static int tns_parser_ctor(struct tns_parser *tns_parser, struct proto *proto)
{
    assert(proto == proto_tns);
    if (0 != parser_ctor(&tns_parser->parser, proto)) return -1;
    tns_parser->c2s_way = UNSET;    // unset
    tns_parser->nb_fields = UNSET;
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

// TTC subcode

#define TTC_DEADBEEF               0xde
#define TTC_LOGIN_PROPERTY         0x01
#define TTC_DATA_REPRESENTATION    0x02
#define TTC_QUERY                  0x03
#define TTC_END_MESSAGE            0x04
#define TTC_ROW_PREFIX             0x06
#define TTC_ROW_DATA               0x07
#define TTC_ROW_DESCRIPTION        0x08
#define TTC_ROW_DESCRIPTION_PREFIX 0x10
#define TTC_CLOSE                  0x11
#define TTC_ROW_RECAP              0x15

// Query sub code

#define TTC_QUERY_FETCH         0x05
#define TTC_QUERY_SQL           0x5e
#define TTC_CLOSE_STATEMENT     0x69

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

#define DROP_DALC(cursor)                                                           \
    if ((status = cursor_read_chunked_string_with_size(cursor, NULL) != PROTO_OK))  \
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
    cursor_drop(cursor, 2);
    unsigned type = cursor_read_u8(cursor);
    cursor_drop(cursor, 3);
    if (type > TNS_TYPE_MAX) return PROTO_PARSE_ERR;

    // Check we have the msg payload
    CHECK_LEN(cursor, len, 8);

    if (out_len) *out_len = len;
    if (out_type) *out_type = type;
    return PROTO_OK;
}

static enum proto_parse_status cursor_read_fix_string(struct cursor *cursor, char **out_str, unsigned str_len)
{
    if (cursor->cap_len < str_len) return PROTO_PARSE_ERR;
    char *str = tempstr();
    unsigned parsed_len = MIN(str_len, TEMPSTR_SIZE - 1);
    cursor_copy(str, cursor, parsed_len);
    str[parsed_len] = '\0';
    if (str_len - parsed_len > 0) {
        cursor_drop(cursor, str_len - parsed_len);
    }
    if(out_str) *out_str = str;
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
    if (cursor->cap_len < 1) return PROTO_PARSE_ERR;
    str_len = cursor_read_u8(cursor);
    SLOG(LOG_DEBUG, "Reading variable str of length %d", str_len);
    if (out_str_len) *out_str_len = str_len;
    return cursor_read_fix_string(cursor, out_str, str_len);
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
static enum proto_parse_status cursor_read_chunked_string(struct cursor *cursor, char **out_str)
{
    char *str = tempstr();
    unsigned pos = 0;
    for (;;) {
        if (cursor->cap_len < 1) return PROTO_PARSE_ERR;
        unsigned str_len = cursor_read_u8(cursor);

        if (cursor->cap_len < str_len) return PROTO_PARSE_ERR;
        for (unsigned i = 0; i < str_len; i++) {
            str[pos + i] = cursor_read_u8(cursor);
        }
        pos += str_len;
        if (str_len < 0x40) break;
    }
    // There seems to be an null terminator when string length is > 0x40
    // However, it can a flag after the string. Ignore it for now.
    if (out_str) *out_str = str;
    return PROTO_OK;
}

/* Read an int prefixed by 1 byte size
 * Size  Int------
 * 0x02  0x01 0xdd
 */
static enum proto_parse_status cursor_read_variable_int(struct cursor *cursor, uint_least64_t *res)
{
    if (cursor->cap_len < 1) return PROTO_PARSE_ERR;
    unsigned len = cursor_read_u8(cursor);
    SLOG(LOG_DEBUG, "Variable len has size %d", len);
    return cursor_read_fix_int_n(cursor, res, len);
}

/* Read a splitted string prefixed by a global variable size
 * Each chunk of string is prefixed by it's size
 * Size of Size  Size  Size  String---  Size  String---
 *         0x01  0x04  0x02  0x40 0x41  0x02  0x50 0x51
 */
static enum proto_parse_status cursor_read_chunked_string_with_size(struct cursor *cursor, char **res)
{
    uint_least64_t size;
    enum proto_parse_status status;
    if (cursor->cap_len < 1) return PROTO_PARSE_ERR;
    status = cursor_read_variable_int(cursor, &size);
    if (status != PROTO_OK) return status;
    if (size > 0) {
        status = cursor_read_chunked_string(cursor, res);
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
    if (cursor->cap_len < 16) return PROTO_PARSE_ERR;
    unsigned version = cursor_read_u16n(cursor);
    info->version_maj = version/100;
    info->version_min = version%100;
    info->set_values |= SQL_VERSION;
    info->set_values |= SQL_REQUEST_STATUS;
    info->request_status = SQL_REQUEST_COMPLETE;
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

static enum proto_parse_status tns_parse_row_prefix(struct cursor *cursor)
{
    enum proto_parse_status status;
    SLOG(LOG_DEBUG, "Parsing Row prefix");

    /* A row prefix contains
     * - 1 byte flag
     * - 6 var
     */
    DROP_FIX(cursor, 1);
    DROP_VARS(cursor, 6);
    return PROTO_OK;
}

static enum proto_parse_status tns_parse_row_data(struct tns_parser *tns_parser, struct cursor *cursor)
{
    enum proto_parse_status status;
    SLOG(LOG_DEBUG, "Parsing row data");

    /* A row data contains :
     * - 1 var for each fields
     */
    DROP_VAR_STRS(cursor, tns_parser->nb_fields);
    return PROTO_OK;
}

static enum proto_parse_status tns_parse_row_description_prefix(struct tns_parser *tns_parser, struct sql_proto_info *info, struct cursor *cursor)
{
    enum proto_parse_status status;
    SLOG(LOG_DEBUG, "Parsing row description prefix");

    unsigned length = cursor_read_u8(cursor);
    DROP_FIX(cursor, length);
    DROP_VAR(cursor);

    uint_least64_t num_fields;
    status = cursor_read_variable_int(cursor, &num_fields);
    if (status != PROTO_OK) return status;
    info->set_values |= SQL_NB_FIELDS;
    info->u.query.nb_fields = num_fields;
    tns_parser->nb_fields = info->u.query.nb_fields;
    SLOG(LOG_DEBUG, "Got %d fields", info->u.query.nb_fields);

    DROP_FIX(cursor, 1);
    for (unsigned i = 0; i < num_fields; i++) {
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

static enum proto_parse_status tns_parse_row_description(struct sql_proto_info *info, struct cursor *cursor)
{
    enum proto_parse_status status;
    SLOG(LOG_DEBUG, "Parsing a row description");
    info->msg_type = SQL_QUERY;

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

static enum proto_parse_status tns_parse_end(struct sql_proto_info *info, struct cursor *cursor)
{
    SLOG(LOG_DEBUG, "Parsing tns end packet");
    info->msg_type = SQL_QUERY;
    enum proto_parse_status status;

    // Sequence
    DROP_VAR(cursor);

    uint_least64_t nb_rows;
    status = cursor_read_variable_int(cursor, &nb_rows);
    if (status != PROTO_OK) return status;
    info->u.query.nb_rows = nb_rows;
    info->set_values |= SQL_NB_ROWS;
    SLOG(LOG_DEBUG, "Nb rows %d", info->u.query.nb_rows);

    uint_least64_t error_code;
    status = cursor_read_variable_int(cursor, &error_code);
    if (status != PROTO_OK) return status;
    SLOG(LOG_DEBUG, "Error code is %"PRIuLEAST64, error_code);

    DROP_VARS(cursor, 4);
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
        while(cursor->cap_len > 1){
            if (isprint(*(cursor->head + 1)))
                break;
            DROP_FIX(cursor, 1);
        }
        status = cursor_read_variable_string(cursor, &error_msg, &error_len);
        if (status != PROTO_OK) return status;
        // Split "ORA-XXXX: msg"
        // Part before : is the error code
        // Part after is the localized message
        char *colon_pos = memchr(error_msg, ':', error_len);
        info->set_values |= SQL_REQUEST_STATUS;
        info->request_status = SQL_REQUEST_ERROR;
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

static enum proto_parse_status tns_parse_sql_query_oci(struct sql_proto_info *info, struct cursor *cursor)
{
    enum proto_parse_status status;
    uint8_t const *new_head = memchr(cursor->head, 0xfe, cursor->cap_len);
    if (new_head == NULL) return PROTO_PARSE_ERR;
    size_t gap_size = new_head - cursor->head;
    SLOG(LOG_DEBUG, "%zu bytes before sql", gap_size);
    DROP_FIX(cursor, gap_size + 1);

    char *sql;
    status = cursor_read_chunked_string(cursor, &sql);
    if (status != PROTO_OK) return status;
    SLOG(LOG_DEBUG, "Sql parsed: %s", sql);
    info->set_values |= SQL_SQL;
    copy_string(info->u.query.sql, sql, sizeof(info->u.query.sql));

    // Drop the rest
    cursor_drop(cursor, cursor->cap_len - 1);

    return PROTO_OK;
}

static enum proto_parse_status tns_parse_sql_query_jdbc(struct sql_proto_info *info, struct cursor *cursor)
{
    enum proto_parse_status status;

    DROP_VAR(cursor);
    DROP_FIX(cursor, 1);

    uint_least64_t sql_len;
    status = cursor_read_variable_int(cursor, &sql_len);
    if (status != PROTO_OK) return status;
    SLOG(LOG_DEBUG, "Size sql %"PRIuLEAST64, sql_len);

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

    // Some unknown bytes
    while (!isprint(*cursor->head)) {
        DROP_FIX(cursor, 1);
    }

    char *sql;
    status = cursor_read_fix_string(cursor, &sql, sql_len);
    if (status != PROTO_OK) return status;
    SLOG(LOG_DEBUG, "Sql parsed: %s", sql);
    info->set_values |= SQL_SQL;
    copy_string(info->u.query.sql, sql, sizeof(info->u.query.sql));

    SLOG(LOG_DEBUG, "Skipping %"PRIuLEAST64" end variable fields", end_len);
    DROP_VARS(cursor, end_len);
    return PROTO_OK;
}

static enum proto_parse_status tns_parse_sql_query(struct sql_proto_info *info, struct cursor *cursor)
{
    // Sequence number
    DROP_FIX(cursor, 1);

    if (cursor->cap_len < 1) return PROTO_PARSE_ERR;
    unsigned option_size = cursor_read_u8(cursor);

    if (option_size > 0x04) {
        // Option is not prefix based, seems like an oci query
        return tns_parse_sql_query_oci(info, cursor);
    } else {
        DROP_FIX(cursor, option_size);
        return tns_parse_sql_query_jdbc(info, cursor);
    }
}

static enum proto_parse_status tns_parse_query(struct tns_parser *tns_parser, struct sql_proto_info *info, struct cursor *cursor)
{
    SLOG(LOG_DEBUG, "Parsing tns query");

    info->msg_type = SQL_UNKNOWN;
    enum proto_parse_status status = PROTO_OK;
    unsigned fun_code = cursor_read_u8(cursor);
    switch (fun_code) {
        case TTC_QUERY_SQL:
            tns_parser->nb_fields = UNSET;
            info->msg_type = SQL_QUERY;
            status = tns_parse_sql_query(info, cursor);
            break;
        case TTC_QUERY_FETCH:
            info->msg_type = SQL_QUERY;
            cursor_drop(cursor, cursor->cap_len);
            break;
        default:
            // Probably initialization queries
            break;
    }
    return status;
}

static enum proto_parse_status tns_parse_login_property(struct sql_proto_info *info, struct cursor *cursor)
{
    SLOG(LOG_DEBUG, "Parsing tns login property");
    // We are only interested in response
    if (info->is_query) return PROTO_OK;

    info->msg_type = SQL_STARTUP;
    // Drop Server version
    DROP_FIX(cursor, 3);
    // Drop Server version text
    uint8_t marker = 0x00;
    enum proto_parse_status status = cursor_drop_until(cursor, &marker, sizeof(marker));
    if (status != PROTO_OK) return status;
    // Drop Null byte
    DROP_FIX(cursor, 1);
    if (cursor->cap_len < 2) return PROTO_PARSE_ERR;
    uint16_t charset = cursor_read_u16le(cursor);
    SLOG(LOG_DEBUG, "Found a charset of 0x%02x", charset);
    switch (charset) {
        case 0x01:
        case 0x02:
        case 0x1f:
        case 0xb2:
            info->u.startup.encoding = SQL_ENCODING_LATIN1;
            break;
        case 0x366:
        case 0x367:
        case 0x369:
            info->u.startup.encoding = SQL_ENCODING_UTF8;
            break;
        default:
            return PROTO_PARSE_ERR;
    }
    info->set_values |= SQL_ENCODING;
    // We don't care of the rest...
    return PROTO_OK;
}

static enum proto_parse_status tns_parse_data(struct tns_parser *tns_parser, struct sql_proto_info *info, struct cursor *cursor,
        unsigned way)
{
    SLOG(LOG_DEBUG, "Parsing TNS data PDU of size %zu", cursor->cap_len);
    enum proto_parse_status status = PROTO_OK;

    // First, read the data flags
    if (cursor->cap_len < 2) return PROTO_PARSE_ERR;
    unsigned flags = cursor_read_u16n(cursor);
    SLOG(LOG_DEBUG, "Data flags = 0x%x", flags);
    if (flags & 0x40) { // End Of File
        if (cursor->cap_len != 0) return PROTO_PARSE_ERR;   // This may be wrong, maybe a command is allowed anyway
        info->msg_type = SQL_EXIT;
        info->set_values |= SQL_REQUEST_STATUS;
        info->request_status = SQL_REQUEST_COMPLETE;
        return PROTO_OK;
    }
    info->msg_type = SQL_UNKNOWN;
    while (status == PROTO_OK && cursor->cap_len) {
        unsigned const ttc_code = cursor_read_u8(cursor);
        SLOG(LOG_DEBUG, "Ttc code = %u", ttc_code);
        switch (ttc_code) {
            case TTC_ROW_PREFIX:
                status = tns_parse_row_prefix(cursor);
                break;
            case TTC_ROW_DATA:
                status = tns_parse_row_data(tns_parser, cursor);
                break;
            case TTC_ROW_DESCRIPTION_PREFIX:
                status = tns_parse_row_description_prefix(tns_parser, info, cursor);
                break;
            case TTC_ROW_RECAP:
                status = tns_parse_row_recap(cursor);
                break;
            case TTC_ROW_DESCRIPTION:
                status = tns_parse_row_description(info, cursor);
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
        }
        info->is_query = way == tns_parser->c2s_way;
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
    unsigned pdu_type;
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
            status = tns_parse_connect(tns_parser, &info, &msg);
            break;
        case TNS_ACCEPT:
            status = tns_parse_accept(tns_parser, &info, &msg);
            break;
        case TNS_DATA:
            status = tns_parse_data(tns_parser, &info, &msg, way);
            break;
        case TNS_RESEND:
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
    if (status != PROTO_OK) SLOG(LOG_DEBUG, "Unknown tns packet");
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
