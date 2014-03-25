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
#include "junkie/proto/sql.h"
#include "junkie/proto/streambuf.h"
#include "junkie/proto/cursor.h"

#undef LOG_CAT
#define LOG_CAT proto_mysql_log_category

LOG_CATEGORY_DEF(proto_mysql);

struct mysql_header {
    uint32_t length;
    uint8_t packet_num;
};

enum query_command {
    COM_QUIT                = 0x01,
    COM_INIT_DB             = 0x02,
    COM_QUERY               = 0x03,
    COM_FIELD_LIST          = 0x04,
    COM_CREATE_DB           = 0x05,
    COM_DROP_DB             = 0x06,
    COM_REFRESH             = 0x07,
    COM_SHUTDOWN            = 0x08,
    COM_STATISTICS          = 0x09,
    COM_PROCESS_INFO        = 0x0a,
    COM_CONNECT             = 0x0b,
    COM_PROCESS_KILL        = 0x0c,
    COM_DEBUG               = 0x0d,
    COM_PING                = 0x0e,
    COM_CHANGE_USER         = 0x11,
    COM_STMT_PREPARE        = 0x16,
    COM_STMT_EXECUTE        = 0x17,
    COM_STMT_SEND_LONG_DATA = 0x18,
    COM_STMT_CLOSE          = 0x19,
    COM_STMT_RESET          = 0x1a,
    COM_STMT_FETCH          = 0x1c,
};

static char const *query_command_2_str(enum query_command command)
{
    switch (command) {
        case COM_QUIT                : return "COM_QUIT";
        case COM_INIT_DB             : return "COM_INIT_DB";
        case COM_QUERY               : return "COM_QUERY";
        case COM_FIELD_LIST          : return "COM_FIELD_LIST";
        case COM_CREATE_DB           : return "COM_CREATE_DB";
        case COM_DROP_DB             : return "COM_DROP_DB";
        case COM_REFRESH             : return "COM_REFRESH";
        case COM_SHUTDOWN            : return "COM_SHUTDOWN";
        case COM_STATISTICS          : return "COM_STATISTICS";
        case COM_PROCESS_INFO        : return "COM_PROCESS_INFO";
        case COM_CONNECT             : return "COM_CONNECT";
        case COM_PROCESS_KILL        : return "COM_PROCESS_KILL";
        case COM_DEBUG               : return "COM_DEBUG";
        case COM_PING                : return "COM_PING";
        case COM_CHANGE_USER         : return "COM_CHANGE_USER";
        case COM_STMT_PREPARE        : return "COM_STMT_PREPARE";
        case COM_STMT_EXECUTE        : return "COM_STMT_EXECUTE";
        case COM_STMT_SEND_LONG_DATA : return "COM_STMT_SEND_LONG_DATA";
        case COM_STMT_CLOSE          : return "COM_STMT_CLOSE";
        case COM_STMT_RESET          : return "COM_STMT_RESET";
        case COM_STMT_FETCH          : return "COM_STMT_FETCH";
        default: return "unknown";
    }
}

struct mysql_parser {
    struct parser parser;
    unsigned c2s_way;       // The way when traffic is going from client to server (UNSET for unset)
    enum phase { NONE, STARTUP, QUERY, EXIT } phase;
    struct streambuf sbuf;
    unsigned nb_eof;        // count the Srv->Clt EOF packets (to parse result sets)
    enum query_command last_command;
};

static char const *mysql_phase_2_str(enum phase phase)
{
    switch (phase) {
        case NONE    : return "NONE";
        case STARTUP : return "STARTUP";
        case QUERY   : return "QUERY";
        case EXIT    : return "EXIT";
        default      : return tempstr_printf("Unknown (%u)", phase);
    }
}

static parse_fun mysql_sbuf_parse;

static int mysql_parser_ctor(struct mysql_parser *mysql_parser, struct proto *proto)
{
    SLOG(LOG_DEBUG, "Constructing mysql_parser@%p", mysql_parser);
    assert(proto == proto_mysql);
    if (0 != parser_ctor(&mysql_parser->parser, proto)) return -1;
    mysql_parser->phase = NONE;
    mysql_parser->c2s_way = UNSET;
    if (0 != streambuf_ctor(&mysql_parser->sbuf, mysql_sbuf_parse, 30000)) return -1;
    mysql_parser->nb_eof = 0;
    mysql_parser->last_command = 0;

    return 0;
}

static struct parser *mysql_parser_new(struct proto *proto)
{
    struct mysql_parser *mysql_parser = objalloc_nice(sizeof(*mysql_parser), "MySQL parsers");
    if (! mysql_parser) return NULL;

    if (-1 == mysql_parser_ctor(mysql_parser, proto)) {
        objfree(mysql_parser);
        return NULL;
    }

    return &mysql_parser->parser;
}

static void mysql_parser_dtor(struct mysql_parser *mysql_parser)
{
    SLOG(LOG_DEBUG, "Destructing mysql_parser@%p", mysql_parser);
    parser_dtor(&mysql_parser->parser);
    streambuf_dtor(&mysql_parser->sbuf);
}

static void mysql_parser_del(struct parser *parser)
{
    struct mysql_parser *mysql_parser = DOWNCAST(parser, parser, mysql_parser);
    mysql_parser_dtor(mysql_parser);
    objfree(mysql_parser);
}

/*
 * Parse
 */

// read a variable-length, checking we have enough room for the value that follows it
static enum proto_parse_status cursor_read_varlen(struct cursor *cursor, uint_least64_t *val_, size_t max_len)
{
    if (max_len < 1) return PROTO_PARSE_ERR;
    CHECK(1);
    uint_least64_t val = cursor_read_u8(cursor);

    if (unlikely_(val > 250)) {
        if (unlikely_(val == 251)) {
            val = 0;    // For NULL column
        } else if (unlikely_(val == 252)) {
            CHECK_LEN(cursor, 2, 1);
            val = cursor_read_u16(cursor);
        } else if (unlikely_(val == 253)) {
            CHECK_LEN(cursor, 3, 1);
            val = cursor_read_u24(cursor);
        } else if (unlikely_(val == 254)) {
            CHECK_LEN(cursor, 8, 1);
            val = cursor_read_u64(cursor);
        } else if (unlikely_(val == 255)) { // can not be 255 since 255 in a field count would mean Error packet (poorly designed encoding for a poorly designed DB)
            return PROTO_PARSE_ERR;
        }
    }

    if (val_) *val_ = val;
    return PROTO_OK;
}

// Read a length-encoded string
static enum proto_parse_status cursor_read_le_string(struct cursor *cursor, char **str_, size_t max_len)
{
    uint_least64_t len;
    enum proto_parse_status status = cursor_read_varlen(cursor, &len, max_len);
    if (status != PROTO_OK) return status;
    // We are supposed to have the whole packet at disposal
    if (cursor->cap_len < len) return PROTO_PARSE_ERR;

    unsigned const l = MIN(TEMPSTR_SIZE - 1, len);
    char *str = tempstr();
    memcpy(str, cursor->head, l);
    for (unsigned s = 0; s < l; s++) {
        if (! isprint(str[s])) str[s] = '.';
    }
    str[l] = '\0';
    cursor_drop(cursor, len);

    if (str_) *str_ = str;
    return PROTO_OK;
}

/* Read a message header, return msg length and packet number, and advance the cursor to the msg payload.
 * return PROTO_TOO_SHORT if the msg content is not available.
 * | 3 bytes | 1 byte     |
 * | Length  | Packet Num |
 */
static enum proto_parse_status read_mysql_header(struct cursor *cursor, struct mysql_header *header)
{
    assert(header);
    SLOG(LOG_DEBUG, "Reading new message");

    CHECK(4);
    header->length = cursor_read_u24(cursor);
    header->packet_num = cursor_read_u8(cursor);

    SLOG(LOG_DEBUG, "... of length %u and packet # %u", header->length, header->packet_num);

    CHECK(header->length);

    return PROTO_OK;
}


/*
 * | 4 bytes    | 1 byte           | Null terminated | 4 bytes   | Null terminated | 2 bytes             |
 * | Msg Header | Protocol version | Version string  | Thread id | Salt            | Server Capabilities |
 *
 * | 1 byte          | 2 bytes       | 13 bytes | Null Terminated |
 * | Server language | Server status | Unused?  | Salt            |
 */
static enum proto_parse_status mysql_parse_init(struct mysql_parser *mysql_parser, struct sql_proto_info *info, unsigned way, uint8_t const *payload, size_t cap_len, size_t unused_ wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    info->msg_type = SQL_STARTUP;

    /* In the initialization phase, we are waiting for the server's greating only */

    if (info->is_query) return PROTO_PARSE_ERR;

    struct cursor cursor;
    cursor_ctor(&cursor, payload, cap_len);
    struct mysql_header header;
    enum proto_parse_status status = read_mysql_header(&cursor, &header);
    if (status != PROTO_OK) return status;
    if (header.packet_num != 0) return PROTO_PARSE_ERR;
    if (header.length < 1) return PROTO_PARSE_ERR;    // should have at least the version number

    info->version_maj = cursor_read_u8(&cursor);
    info->version_min = 0;
    info->set_values |= SQL_VERSION;

    mysql_parser->phase = STARTUP;
    return proto_parse(NULL, &info->info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
}

/*
 * The error message part of the server response
 * | 2 bytes    | 1 byte | 5 bytes         | Null terminated |
 * | Error code | 0x23   | Sql error state | Error Message   |
 */
static enum proto_parse_status mysql_parse_error(struct sql_proto_info *info, struct cursor *cursor, size_t packet_len)
{
    SLOG(LOG_DEBUG, "Parse mysql error");
    #define MYSQL_ERROR_HEADER (2 + 1 + SQL_ERROR_SQL_STATUS_SIZE)
    enum proto_parse_status status;
    if (packet_len <= MYSQL_ERROR_HEADER) return PROTO_PARSE_ERR;
    sql_set_request_status(info, SQL_REQUEST_ERROR);

    uint16_t error_code = cursor_read_u16(cursor);
    // Since protocol specific error code can contains characters, we need to
    // transform it to string
    snprintf(info->error_code, sizeof(info->error_code), "%d", error_code);
    info->set_values |= SQL_ERROR_CODE;

    // Drop the # after error code
    cursor_drop(cursor, 1);

    char *str;
    status = cursor_read_fixed_string(cursor, &str, SQL_ERROR_SQL_STATUS_SIZE);
    if (status != PROTO_OK) return status;
    strncpy(info->error_sql_status, str, sizeof(info->error_sql_status));
    info->set_values |= SQL_ERROR_SQL_STATUS;

    // The end of message is the error message
    size_t message_len = packet_len - MYSQL_ERROR_HEADER;
    status = cursor_read_fixed_string(cursor, &str, message_len);
    if (status != PROTO_OK) return status;
    strncpy(info->error_message, str, sizeof(info->error_message));
    info->set_values |= SQL_ERROR_MESSAGE;

    return PROTO_OK;
}

static unsigned command_to_expected_eof(enum query_command command)
{
    switch (command) {
        case COM_FIELD_LIST: return 1;
        default: return 2;
    }
}

/*
 * Ok pdu
 * | 4 bytes    | 1 byte      | 2 bytes       | 2 bytes  |
 * | Msg header | Status 0x00 | Server status | Warnings |
 *
 * Error pdu
 * | 4 bytes    | 1 byte | 2 bytes    | 1 byte | 4 bytes   | Null terminated |
 * | Msg header | 0xff   | Error code | 0x23   | Sql state | Error Message   |
 *
 * Eof marker
 * | 4 bytes    | 1 byte | 2 bytes  | 2 bytes       |
 * | Msg header | 0xfe   | Warnings | Server status |
 *
 * Prepare statement response
 * | 4 bytes     | 1 byte      | 4 bytes      | 2 bytes       | 2 bytes           | 1 byte   | 2 bytes        |
 * | Msg header  | Header 0x00 | Statement id | Number fields | Number parameters | reserved | Warning counts |
 * Parameter definition blocks
 *
 * Execute statement response
 * | 4 bytes    | 1 byte           |
 * | Msg header | Number of fields |
 * Column description
 * Eof Marker
 * Binary data row * nb rows
 * | 4 bytes    | 1 byte      | variable     |
 * | Msg header | header 0x00 | Bitmap value |
 *
 * Query response pdu
 * | 4 bytes    | 1 byte           |
 * | Msg header | Number of fields |
 * Column description * nb columns (just skip)
 * Eof Marker
 * Row data * nb rows
 * | 4 bytes    | Prefixed length string | Prefixed length string | ... |
 * | Msg header | Catalog                | Database               | ... |
 * Eof Marker
 */
static enum proto_parse_status mysql_parse_server_response(struct mysql_parser *mysql_parser, struct cursor *cursor,
        struct sql_proto_info *info)
{
    SLOG(LOG_DEBUG, "Parse mysql server response, last query %s", query_command_2_str(mysql_parser->last_command));
    struct mysql_header header;
    enum proto_parse_status status = read_mysql_header(cursor, &header);
    if (status != PROTO_OK) return status;
    uint8_t const *msg_end = cursor->head + header.length;
    if (header.packet_num == 1) mysql_parser->nb_eof = 0;

    if (header.length < 1) return PROTO_PARSE_ERR;
    unsigned res = cursor_peek_u8(cursor, 0);
    if (res == 0xff) {
        SLOG(LOG_DEBUG, "Got an error pdu");
        cursor_drop(cursor, 1);
        status = mysql_parse_error(info, cursor, header.length - 1);
        if (status != PROTO_OK) return status;
    } else if (res == 0xfe) {
        if (header.length != 5) return PROTO_PARSE_ERR;
        mysql_parser->nb_eof ++;
        SLOG(LOG_DEBUG, "Got an eof pdu, count is %u", mysql_parser->nb_eof);
    } else if (mysql_parser->last_command == COM_STMT_PREPARE) {
        // Do nothing, fields and rows will be fetch from execute
    } else if (mysql_parser->last_command == COM_STMT_EXECUTE) {
        SLOG(LOG_DEBUG, "Got execute statement response");
        if (header.packet_num == 1) {
            uint_least64_t field_count;
            if (PROTO_OK != (status = cursor_read_varlen(cursor, &field_count, header.length))) return status;
            sql_set_field_count(info, field_count);
        } else if (res == 0x00 && mysql_parser->nb_eof == 1) {
            sql_increment_row_count(info, 1);
        }
    } else if (mysql_parser->last_command == COM_FIELD_LIST) {
        sql_increment_field_count(info, 1);
    } else if (res > 0 && mysql_parser->last_command == COM_QUERY) { // Query pdu
        SLOG(LOG_DEBUG, "Got query response, eof %u, pkt number %u", mysql_parser->nb_eof, header.packet_num);
        if (header.packet_num == 1 && msg_end == (cursor->head + 1)) {  // result set header
            // We must re-read the field count since it's actually a varlen binary
            uint_least64_t field_count;
            if (PROTO_OK != (status = cursor_read_varlen(cursor, &field_count, header.length))) return status;
            sql_set_field_count(info, field_count);
        } else if (mysql_parser->nb_eof == 1) { // Row data pdu
            sql_increment_row_count(info, 1);
        }
    } else if (res == 0) { // OK packet
        SLOG(LOG_DEBUG, "Got an ok response packet");
        cursor_drop(cursor, 1);
        sql_set_request_status(info, SQL_REQUEST_COMPLETE);
        mysql_parser->phase = QUERY;
        if (mysql_parser->phase == QUERY) {
            uint_least64_t nb_rows;
            status = cursor_read_varlen(cursor, &nb_rows, header.length - 1);
            if (status != PROTO_OK) return status;
            sql_set_row_count(info, nb_rows); // number of affected rows
        }
    }
    // We expect for query:
    // - 1 eof for field description
    // - 1 eof for rows
    if (mysql_parser->nb_eof == command_to_expected_eof(mysql_parser->last_command)) {
        SLOG(LOG_DEBUG, "Query is completed");
        sql_set_request_status(info, SQL_REQUEST_COMPLETE);
    }
    if (cursor->head < msg_end) cursor_drop(cursor, msg_end - cursor->head);

    return PROTO_OK;
}

static enum sql_encoding mysql_charset_to_encoding(unsigned charset)
{
    switch (charset) {
        case 0x05:
        case 0x08:
            return SQL_ENCODING_LATIN1;
        case 0x21:
            return SQL_ENCODING_UTF8;
        default:
            return SQL_ENCODING_UNKNOWN;
    }
}

/*
 * Client login:
 * | 4 bytes    | 2 bytes             | 2 bytes               | 4 bytes     | 0x17 bytes  |
 * | Msg header | Client capabilities | Extended capabilities | Max packets | Useless gap |
 *
 * | 1 byte  | Null terminated | Null terminated | Null terminated |
 * | Charset | Username        | Password        | Schema          |
 */
static enum proto_parse_status mysql_parse_client_login(struct cursor *cursor, struct sql_proto_info *info)
{
    SLOG(LOG_DEBUG, "Parse mysql client login");
    struct mysql_header header;
    enum proto_parse_status status = read_mysql_header(cursor, &header);
    if (status != PROTO_OK) return status;

    uint8_t const *msg_end = cursor->head + header.length;
    if (header.packet_num != 1) {
        SLOG(LOG_DEBUG, "Wrong packet number, expected 1, got %d", header.packet_num);
        return PROTO_PARSE_ERR;
    }
    if (header.length < 0x20) return PROTO_PARSE_ERR;

    cursor_drop(cursor, 8);
    SLOG(LOG_DEBUG, "Reading encoding charset");
    unsigned charset = cursor_read_u8(cursor);
    sql_set_encoding(info, mysql_charset_to_encoding(charset));

    // jump to interresting bits
    cursor_drop(cursor, 0x17);
    char *str;
    status = cursor_read_string(cursor, &str, msg_end - cursor->head);
    if (status != PROTO_OK) return status;
    info->set_values |= SQL_USER;
    snprintf(info->u.startup.user, sizeof(info->u.startup.user), "%s", str);
    status = cursor_read_le_string(cursor, &str, msg_end - cursor->head);
    if (status != PROTO_OK) return status;
    info->set_values |= SQL_PASSWD;
    snprintf(info->u.startup.passwd, sizeof(info->u.startup.passwd), "%s", str);
    status = cursor_read_string(cursor, &str, msg_end - cursor->head);
    if (status != PROTO_OK) return status;
    info->set_values |= SQL_DBNAME;
    snprintf(info->u.startup.dbname, sizeof(info->u.startup.dbname), "%s", str);
    if (cursor->head < msg_end) cursor_drop(cursor, msg_end - cursor->head);

    return PROTO_OK;
}

/*
 * In the startup phase (after the server greating), we are expecting:
 * - the client authentication packet or
 * - the server OK/Error response
 */
static enum proto_parse_status mysql_parse_startup(struct mysql_parser *mysql_parser, struct sql_proto_info *info, unsigned way, uint8_t const *payload, size_t cap_len, size_t unused_ wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    SLOG(LOG_DEBUG, "Parse mysql startup");
    info->msg_type = SQL_STARTUP;

    struct cursor cursor;
    cursor_ctor(&cursor, payload, cap_len);
    enum proto_parse_status status;

    SLOG(LOG_DEBUG, "Set values before %u", info->set_values);
    if (info->is_query) {
        status = mysql_parse_client_login(&cursor, info);
    } else {
        status = mysql_parse_server_response(mysql_parser, &cursor, info);
    }
    if (status != PROTO_OK) return status;
    SLOG(LOG_DEBUG, "Set values after %u", info->set_values);

    return proto_parse(NULL, &info->info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
}

static char const *com_refresh_2_str(uint8_t code)
{
    switch (code) {
        case 0x01: return "REFRESH GRANT";
        case 0x02: return "REFRESH LOG";
        case 0x04: return "REFRESH TABLES";
        case 0x08: return "REFRESH HOSTS";
        case 0x10: return "REFRESH STATUS";
        case 0x20: return "REFRESH THREADS";
        case 0x40: return "REFRESH SLAVE";
        case 0x80: return "REFRESH MASTER";
    }
    return NULL;
}

static char const *com_shutdown_2_str(uint8_t code)
{
    switch (code) {
        case 0x00: return "SHUTDOWN DEFAULT";
        case 0x01: return "SHUTDOWN WAIT CONNECTIONS";
        case 0x02: return "SHUTDOWN WAIT TRANSACTIONS";
        case 0x08: return "SHUTDOWN WAIT UPDATES";
        case 0x10: return "SHUTDOWN WAIT ALL BUFFERS";
        case 0x11: return "SHUTDOWN WAIT CRITICAL BUFFERS";
        case 0xFE: return "KILL QUERY";
        case 0xFF: return "KILL CONNECTION";
    }
    return NULL;
}

static enum proto_parse_status mysql_parse_client_query(struct mysql_parser *mysql_parser, struct sql_proto_info *info, struct cursor *cursor)
{
    SLOG(LOG_DEBUG, "Parse client query");
    struct mysql_header header;
    enum proto_parse_status status = read_mysql_header(cursor, &header);
    if (status != PROTO_OK) return status;
    uint8_t const *const msg_end = cursor->head + header.length;

    if (header.packet_num != 0) return PROTO_PARSE_ERR;    // TODO: are there some commands that are split amongst several packets ?
    if (header.length-- < 1) return PROTO_PARSE_ERR;
    enum query_command command = cursor_read_u8(cursor);
    mysql_parser->last_command = command;
    switch (command) {
        case COM_STMT_PREPARE:
        case COM_QUERY:
            sql_set_query(info, "%.*s", (int)header.length, cursor->head);
            break;
        case COM_QUIT:
            {
                if (header.length != 0) return PROTO_PARSE_ERR;
                mysql_parser->phase = EXIT;
                info->msg_type = SQL_EXIT;
                sql_set_request_status(info, SQL_REQUEST_COMPLETE);
                return PROTO_OK;
            }
        case COM_INIT_DB:
            sql_set_query(info, "USE %.*s", (int)header.length, cursor->head);
            break;
        case COM_FIELD_LIST:
            sql_set_query(info, "SHOW FIELDS FROM %.*s", (int)header.length, cursor->head);
            break;
        case COM_CREATE_DB:
            sql_set_query(info, "CREATE DATABASE %.*s", (int)header.length, cursor->head);
            break;
        case COM_DROP_DB:
            sql_set_query(info, "DROP DATABASE %.*s", (int)header.length, cursor->head);
            break;
        case COM_REFRESH:
            {
                if (header.length-- < 1) return PROTO_PARSE_ERR;
                char const *sql = com_refresh_2_str(cursor_read_u8(cursor));
                if (! sql) return PROTO_PARSE_ERR;
                sql_set_query(info, "%s", sql);
            }
            break;
        case COM_SHUTDOWN:
            {
                if (header.length-- < 1) return PROTO_PARSE_ERR;
                char const *sql = com_shutdown_2_str(cursor_read_u8(cursor));
                if (! sql) return PROTO_PARSE_ERR;
                sql_set_query(info, "%s", sql);
            }
            break;
        case COM_STATISTICS:
            if (header.length != 0) return PROTO_PARSE_ERR;
            sql_set_query(info, "STATISTICS");
            break;
        case COM_PROCESS_INFO:
            if (header.length != 0) return PROTO_PARSE_ERR;
            sql_set_query(info, "SHOW PROCESSLIST");
            break;
        case COM_CONNECT:
            break;
        case COM_PROCESS_KILL:
            {
                if (header.length != 4) return PROTO_PARSE_ERR;
                uint32_t pid = cursor_read_u32(cursor);
                sql_set_query(info, "KILL %"PRIu32, pid);
            }
            break;
        case COM_DEBUG:
            if (header.length != 0) return PROTO_PARSE_ERR;
            sql_set_query(info, "DEBUG");
            break;
        case COM_PING:
            if (header.length != 0) return PROTO_PARSE_ERR;
            sql_set_query(info, "PING");
            break;
        case COM_CHANGE_USER:
            // TODO: fetch new user, password and dbname, and reset the phase to startup ?
            break;
        case COM_STMT_EXECUTE:
        case COM_STMT_CLOSE:
        case COM_STMT_SEND_LONG_DATA:
        case COM_STMT_RESET:
        case COM_STMT_FETCH:
            break;
        default:
            SLOG(LOG_DEBUG, "Unknown command %u", command);
            return PROTO_PARSE_ERR;
    }
    cursor_drop(cursor, msg_end - cursor->head);
    return PROTO_OK;
}

/*
 * In query phase, we expect:
 * - From client
 * | 4 bytes    | 1 byte  | Variable  |
 * | Msg header | Command | Statement |
 */
static enum proto_parse_status mysql_parse_query(struct mysql_parser *mysql_parser, struct sql_proto_info *info, unsigned way, uint8_t const *payload, size_t cap_len, size_t unused_ wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    info->msg_type = SQL_QUERY;

    struct cursor cursor;
    cursor_ctor(&cursor, payload, cap_len);

    enum proto_parse_status status = PROTO_OK;
    uint8_t const * last_start = cursor.head;

    while (! cursor_is_empty(&cursor)) {
        last_start = cursor.head;
        if (info->is_query) {
            status = mysql_parse_client_query(mysql_parser, info, &cursor);
        } else {
            status = mysql_parse_server_response(mysql_parser, &cursor, info);
        }
        if (status != PROTO_OK) break;
    }
    if (status == PROTO_PARSE_ERR) return PROTO_PARSE_ERR;
    if (status == PROTO_TOO_SHORT) {
        SLOG(LOG_DEBUG, "Payload too short for parsing message, will restart");
        status = proto_parse(NULL, &info->info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);    // ack what we had so far
        streambuf_set_restart(&mysql_parser->sbuf, way, last_start, true);
        return PROTO_OK;
    }

    return proto_parse(NULL, &info->info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
}

static enum phase guess_phase(uint8_t pkt_number, uint8_t first_byte, struct sql_proto_info *info)
{
    // Probably protocol version from greetings
    if (pkt_number == 0 && (first_byte == 9 || first_byte == 10) && !info->is_query) {
        return NONE;
    }
    // On startup, server should have initiated connection
    if ((pkt_number == 1 && info->is_query) || (pkt_number == 2 && !info->is_query)) {
        return STARTUP;
    }
    return QUERY;
}

static enum proto_parse_status mysql_sbuf_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct mysql_parser *mysql_parser = DOWNCAST(parser, parser, mysql_parser);
    if (cap_len < 5) return PROTO_PARSE_ERR;

    // If this is the first time we are called, init c2s_way
    if (mysql_parser->c2s_way == UNSET) {
        struct tcp_proto_info const *tcp_info = DOWNCAST(parent, info, tcp_proto_info);
        if (tcp_info) mysql_parser->c2s_way = tcp_info->to_srv;
        else mysql_parser->c2s_way = !way;
        SLOG(LOG_DEBUG, "First packet, init c2s_way to %u", mysql_parser->c2s_way);
    }

    // Now build the proto_info
    struct sql_proto_info info;
    proto_info_ctor(&info.info, parser, parent, wire_len, 0);
    info.is_query = way == mysql_parser->c2s_way;
    info.set_values = 0;

    if (mysql_parser->phase == NONE) {
        // Try to guess from packet number and first byte
        mysql_parser->phase = guess_phase(payload[3], payload[4], &info);
    }

    SLOG(LOG_DEBUG, "Parse as phase %s, is query %d", mysql_phase_2_str(mysql_parser->phase), info.is_query);
    switch (mysql_parser->phase) {
        case NONE:    return mysql_parse_init   (mysql_parser, &info, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);
        case STARTUP: return mysql_parse_startup(mysql_parser, &info, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);
        case QUERY:   return mysql_parse_query  (mysql_parser, &info, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);
        case EXIT:    return PROTO_PARSE_ERR;   // we do not expect payload after a termination message
    }

    return PROTO_PARSE_ERR;
}

static enum proto_parse_status mysql_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct mysql_parser *mysql_parser = DOWNCAST(parser, parser, mysql_parser);
    if (cap_len == 0 && wire_len > 0) return PROTO_TOO_SHORT;   // We do not know how to handle pure gaps

    enum proto_parse_status const status = streambuf_add(&mysql_parser->sbuf, parser, parent, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);
    return status;
}

/*
 * Construction/Destruction
 */

static struct proto proto_mysql_;
struct proto *proto_mysql = &proto_mysql_;
static struct port_muxer mysql_tcp_muxer;

void mysql_init(void)
{
    log_category_proto_mysql_init();

    static struct proto_ops const ops = {
        .parse       = mysql_parse,
        .parser_new  = mysql_parser_new,
        .parser_del  = mysql_parser_del,
        .info_2_str  = sql_info_2_str,
        .info_addr   = sql_info_addr
    };
    proto_ctor(&proto_mysql_, &ops, "MySQL", PROTO_CODE_MYSQL);
    port_muxer_ctor(&mysql_tcp_muxer, &tcp_port_muxers, 3306, 3306, proto_mysql);
}

void mysql_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    port_muxer_dtor(&mysql_tcp_muxer, &tcp_port_muxers);
    proto_dtor(&proto_mysql_);
#   endif
    log_category_proto_mysql_fini();
}

