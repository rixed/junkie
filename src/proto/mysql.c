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

struct mysql_parser {
    struct parser parser;
    unsigned c2s_way;       // The way when traffic is going from client to server (UNSET for unset)
    enum phase { NONE, STARTUP, QUERY, EXIT } phase;
    struct streambuf sbuf;
    unsigned nb_eof;        // count the Srv->Clt EOF packets (to parse result sets)
    unsigned expected_eof;  // Expected EOF packets for response
};

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
    mysql_parser->expected_eof = 2;

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

#define COM_QUIT         0x01
#define COM_INIT_DB      0x02
#define COM_QUERY        0x03
#define COM_FIELD_LIST   0x04
#define COM_CREATE_DB    0x05
#define COM_DROP_DB      0x06
#define COM_REFRESH      0x07
#define COM_SHUTDOWN     0x08
#define COM_STATISTICS   0x09
#define COM_PROCESS_INFO 0x0a
#define COM_CONNECT      0x0b
#define COM_PROCESS_KILL 0x0c
#define COM_DEBUG        0x0d
#define COM_PING         0x0e
#define COM_CHANGE_USER  0x11
#define COM_STMT_PREPARE 0x16
#define COM_STMT_EXECUTE 0x17
#define COM_STMT_FETCH   0x1c

// read a variable-length, checking we have enough room for the value that follows it
static enum proto_parse_status cursor_read_varlen(struct cursor *cursor, uint_least64_t *val_, size_t max_len)
{
    if (max_len < 1) return PROTO_PARSE_ERR;
    CHECK_LEN(cursor, 1, 0);
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

// Read a fixed length string up
static enum proto_parse_status cursor_read_fixed_string(struct cursor *cursor, char **str_, size_t len)
{
    if (cursor->cap_len < len) return PROTO_PARSE_ERR;
    if (str_) {
        char *str = tempstr();
        unsigned const l = MIN(TEMPSTR_SIZE - 1, len);
        memcpy(str, cursor->head, l);
        str[l] = '\0';
        *str_ = str;
    }
    cursor_drop(cursor, len);
    return PROTO_OK;
}

/* Read a message header, return msg length and packet number, and advance the cursor to the msg payload.
 * return PROTO_TOO_SHORT if the msg content is not available. */
static enum proto_parse_status cursor_read_msg(struct cursor *cursor, unsigned *packet_num_, size_t *len_)
{
    SLOG(LOG_DEBUG, "Reading new message");

    CHECK_LEN(cursor, 4, 0);
    size_t len = cursor_read_u24(cursor);
    unsigned packet_num = cursor_read_u8(cursor);

    SLOG(LOG_DEBUG, "... of length %zu and packet # %u", len, packet_num);

    if (len_) *len_ = len;
    if (packet_num_) *packet_num_ = packet_num;

    CHECK_LEN(cursor, len, 4);

    return PROTO_OK;
}

static enum proto_parse_status mysql_parse_init(struct mysql_parser *mysql_parser, struct sql_proto_info *info, unsigned way, uint8_t const *payload, size_t cap_len, size_t unused_ wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    info->msg_type = SQL_STARTUP;

    /* In the initialization phase, we are waiting for the server's greating only */

    if (info->is_query) return PROTO_PARSE_ERR;

    struct cursor cursor;
    cursor_ctor(&cursor, payload, cap_len);
    unsigned packet_num;
    size_t packet_len;
    enum proto_parse_status status = cursor_read_msg(&cursor, &packet_num, &packet_len);
    if (status != PROTO_OK) return status;
    assert(cursor.cap_len >= packet_len);
    if (packet_num != 0) return PROTO_PARSE_ERR;
    if (packet_len < 1) return PROTO_PARSE_ERR;    // should have at least the version number

    info->version_maj = cursor_read_u8(&cursor);
    info->version_min = 0;
    info->set_values |= SQL_VERSION;

    mysql_parser->phase = STARTUP;

    return proto_parse(NULL, &info->info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
}

// We expect
// 2 bytes   Error code
// 1 byte    # character
// 5 bytes   Sql error state
// Variable  Error message
static enum proto_parse_status mysql_parse_error(struct sql_proto_info *info, struct cursor *cursor, size_t packet_len)
{
    #define MYSQL_ERROR_HEADER (2 + 1 + SQL_ERROR_SQL_STATUS_SIZE)
    enum proto_parse_status status;
    if (packet_len <= MYSQL_ERROR_HEADER) return PROTO_PARSE_ERR;
    info->set_values |= SQL_REQUEST_STATUS;
    info->request_status = SQL_REQUEST_ERROR;

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

static enum proto_parse_status mysql_parse_startup(struct mysql_parser *mysql_parser, struct sql_proto_info *info, unsigned way, uint8_t const *payload, size_t cap_len, size_t unused_ wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    info->msg_type = SQL_STARTUP;

    /* In the startup phase (after the server greating), we are expecting :
     * - the client authentication packet or
     * - the server OK/Error response */
    struct cursor cursor;
    cursor_ctor(&cursor, payload, cap_len);
    unsigned packet_num;
    size_t packet_len;
    enum proto_parse_status status = cursor_read_msg(&cursor, &packet_num, &packet_len);
    if (status != PROTO_OK) return status;
    assert(cursor.cap_len >= packet_len);

    if (info->is_query) {
        uint8_t const *msg_end = cursor.head + packet_len;
        if (packet_num != 1) {
            SLOG(LOG_DEBUG, "Wrong packet number, expected 1, got %d", packet_num);
            return PROTO_PARSE_ERR;
        }
        if (packet_len < 32) return PROTO_PARSE_ERR;

        cursor_drop(&cursor, 8);
        SLOG(LOG_DEBUG, "Reading encoding charset");
        unsigned charset = cursor_read_u8(&cursor);
        info->set_values |= SQL_ENCODING;
        info->u.startup.encoding = mysql_charset_to_encoding(charset);

        // jump to interresting bits
        cursor_drop(&cursor, 23);
        char *str;
        status = cursor_read_string(&cursor, &str, msg_end - cursor.head);
        if (status != PROTO_OK) return status;
        info->set_values |= SQL_USER;
        snprintf(info->u.startup.user, sizeof(info->u.startup.user), "%s", str);
        status = cursor_read_le_string(&cursor, &str, msg_end - cursor.head);
        if (status != PROTO_OK) return status;
        info->set_values |= SQL_PASSWD;
        snprintf(info->u.startup.passwd, sizeof(info->u.startup.passwd), "%s", str);
        status = cursor_read_string(&cursor, &str, msg_end - cursor.head);
        if (status != PROTO_OK) return status;
        info->set_values |= SQL_DBNAME;
        snprintf(info->u.startup.dbname, sizeof(info->u.startup.dbname), "%s", str);
    } else {
        if (packet_num != 2) {
            SLOG(LOG_DEBUG, "Wrong packet number, expected 2, got %d", packet_num);
            return PROTO_PARSE_ERR;
        }
        if (packet_len-- < 1) return PROTO_PARSE_ERR;
        unsigned res = cursor_read_u8(&cursor);
        if (res == 0) { // OK packet
            info->set_values |= SQL_REQUEST_STATUS;
            info->request_status = SQL_REQUEST_COMPLETE;
            mysql_parser->phase = QUERY;
        } else { // Error packet
            if (res != 0xff) return PROTO_PARSE_ERR;
            status = mysql_parse_error(info, &cursor, packet_len);
            if (status != PROTO_OK) return status;
        }
    }

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

static enum proto_parse_status mysql_parse_query(struct mysql_parser *mysql_parser, struct sql_proto_info *info, unsigned way, uint8_t const *payload, size_t cap_len, size_t unused_ wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    info->msg_type = SQL_QUERY;

    /* In QUERY phase we expect :
     * - a command packet from client
     * - OK, Error or result set packets from server */
    struct cursor cursor;
    cursor_ctor(&cursor, payload, cap_len);

    while (! cursor_is_empty(&cursor)) {
        uint8_t const *const msg_start = cursor.head;
        unsigned packet_num;
        size_t packet_len;
        enum proto_parse_status status = cursor_read_msg(&cursor, &packet_num, &packet_len);
        if (status == PROTO_PARSE_ERR) return PROTO_PARSE_ERR;
        if (status == PROTO_TOO_SHORT) {
            SLOG(LOG_DEBUG, "Payload too short for parsing message, will restart");
            status = proto_parse(NULL, &info->info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);    // ack what we had so far
            streambuf_set_restart(&mysql_parser->sbuf, way, msg_start, true);
            return PROTO_OK;
        }

        uint8_t const *const msg_end = cursor.head + packet_len;

        if (info->is_query) {
            if (packet_num != 0) return PROTO_PARSE_ERR;    // TODO: are there some commands that are split amongst several packets ?
            if (packet_len-- < 1) return PROTO_PARSE_ERR;
            unsigned command = cursor_read_u8(&cursor);
            if (command > COM_STMT_FETCH) return PROTO_PARSE_ERR;
            info->set_values |= SQL_SQL;
            if (command == COM_QUERY || command == COM_STMT_PREPARE) {
                snprintf(info->u.query.sql, sizeof(info->u.query.sql), "%.*s", (int)packet_len, cursor.head);
            } else if (command == COM_INIT_DB) {
                snprintf(info->u.query.sql, sizeof(info->u.query.sql), "USE %.*s", (int)packet_len, cursor.head);
            } else if (command == COM_FIELD_LIST) {
                snprintf(info->u.query.sql, sizeof(info->u.query.sql), "SHOW FIELDS FROM %.*s", (int)packet_len, cursor.head);
            } else if (command == COM_CREATE_DB) {
                snprintf(info->u.query.sql, sizeof(info->u.query.sql), "CREATE DATABASE %.*s", (int)packet_len, cursor.head);
            } else if (command == COM_DROP_DB) {
                snprintf(info->u.query.sql, sizeof(info->u.query.sql), "DROP DATABASE %.*s", (int)packet_len, cursor.head);
            } else if (command == COM_REFRESH) {
                if (packet_len-- < 1) return PROTO_PARSE_ERR;
                char const *sql = com_refresh_2_str(cursor_read_u8(&cursor));
                if (! sql) return PROTO_PARSE_ERR;
                snprintf(info->u.query.sql, sizeof(info->u.query.sql), "%s", sql);
            } else if (command == COM_SHUTDOWN) {
                if (packet_len-- < 1) return PROTO_PARSE_ERR;
                char const *sql = com_shutdown_2_str(cursor_read_u8(&cursor));
                if (! sql) return PROTO_PARSE_ERR;
                snprintf(info->u.query.sql, sizeof(info->u.query.sql), "%s", sql);
            } else if (command == COM_STATISTICS) {
                if (packet_len != 0) return PROTO_PARSE_ERR;
                snprintf(info->u.query.sql, sizeof(info->u.query.sql), "STATISTICS");
            } else if (command == COM_PROCESS_INFO) {
                if (packet_len != 0) return PROTO_PARSE_ERR;
                snprintf(info->u.query.sql, sizeof(info->u.query.sql), "SHOW PROCESSLIST");
            } else if (command == COM_PROCESS_KILL) {
                if (packet_len != 4) return PROTO_PARSE_ERR;
                uint32_t pid = cursor_read_u32(&cursor);
                snprintf(info->u.query.sql, sizeof(info->u.query.sql), "KILL %"PRIu32, pid);
            } else if (command == COM_DEBUG) {
                if (packet_len != 0) return PROTO_PARSE_ERR;
                snprintf(info->u.query.sql, sizeof(info->u.query.sql), "DEBUG");
            } else if (command == COM_PING) {
                if (packet_len != 0) return PROTO_PARSE_ERR;
                snprintf(info->u.query.sql, sizeof(info->u.query.sql), "PING");
            } else if (command == COM_CHANGE_USER) {
                // TODO: fetch new user, password and dbname, and reset the phase to startup ?
            } else if (command == COM_QUIT) {
                if (packet_len != 0) return PROTO_PARSE_ERR;
                mysql_parser->phase = EXIT;
                info->msg_type = SQL_EXIT;
                info->set_values ^= SQL_SQL;
                info->set_values |= SQL_REQUEST_STATUS;
                info->request_status = SQL_REQUEST_COMPLETE;
                break;
            } else {
                info->set_values ^= SQL_SQL;
            }
            if ( command == COM_FIELD_LIST ) {
                mysql_parser->expected_eof = 1;
            } else {
                mysql_parser->expected_eof = 2;
            }
        } else {    // packet from server to client
            if (packet_len-- < 1) return PROTO_PARSE_ERR;
            unsigned field_count = cursor_read_u8(&cursor);
            if (field_count == 0) { // Ok packet
                uint_least64_t nb_rows;
                status = cursor_read_varlen(&cursor, &nb_rows, packet_len);
                if (status != PROTO_OK) return status;
                info->set_values |= SQL_NB_ROWS;    // number of affected rows
                info->u.query.nb_rows = nb_rows;
            } else if (field_count == 0xff) {   // Error packet
                status = mysql_parse_error(info, &cursor, packet_len);
                if (status != PROTO_OK) return status;
            } else if (field_count == 0xfe) {   // EOF packet
                if (packet_len != 4) return PROTO_PARSE_ERR;
                mysql_parser->nb_eof ++;
            } else {    // result set/field set/row data packet
                // We must re-read the field count since it's actually a varlen binary
                cursor_rollback(&cursor, 1);
                packet_len ++;
                uint_least64_t field_count;
                status = cursor_read_varlen(&cursor, &field_count, packet_len+1);
                if (packet_num == 1) {  // result set header
                    info->set_values |= SQL_NB_FIELDS;
                    info->u.query.nb_fields = field_count;
                    mysql_parser->nb_eof = 0;
                } else {
                    if (mysql_parser->nb_eof == 0) {    // Field packet
                        // not interresting
                    } else if (mysql_parser->nb_eof == 1) { // Row data packet
                        if (! (info->set_values & SQL_NB_ROWS)) {
                            info->set_values |= SQL_NB_ROWS;
                            info->u.query.nb_rows = 0;
                        }
                        info->u.query.nb_rows ++;
                    } else return PROTO_PARSE_ERR;
                }
            }
            // An eof for field description and an eof for rows
            if (mysql_parser->nb_eof == mysql_parser->expected_eof) {
                SLOG(LOG_DEBUG, "Query is completed");
                info->set_values |= SQL_REQUEST_STATUS;
                info->request_status = SQL_REQUEST_COMPLETE;
            }
        }
        cursor_drop(&cursor, msg_end - cursor.head);
    }
    return proto_parse(NULL, &info->info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
}

static enum proto_parse_status mysql_sbuf_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct mysql_parser *mysql_parser = DOWNCAST(parser, parser, mysql_parser);

    // If this is the first time we are called, init c2s_way
    if (mysql_parser->c2s_way == UNSET) {
        mysql_parser->c2s_way = !way;
        SLOG(LOG_DEBUG, "First packet, init c2s_way to %u", mysql_parser->c2s_way);
    }

    // Now build the proto_info
    struct sql_proto_info info;
    proto_info_ctor(&info.info, parser, parent, wire_len, 0);
    info.is_query = way == mysql_parser->c2s_way;
    info.set_values = 0;

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
