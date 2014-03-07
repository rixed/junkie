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
#include <arpa/inet.h>  // for ntohl
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
#define LOG_CAT proto_pgsql_log_category

LOG_CATEGORY_DEF(proto_pgsql);

struct pgsql_parser {
    struct parser parser;
    unsigned c2s_way;       // The way when traffic is going from client to server (UNSET for unset)
    enum phase { NONE, STARTUP, QUERY, EXIT } phase;
    struct streambuf sbuf;
};

static parse_fun pg_sbuf_parse;

static int pg_parser_ctor(struct pgsql_parser *pg_parser, struct proto *proto)
{
    assert(proto == proto_pgsql);
    if (0 != parser_ctor(&pg_parser->parser, proto)) return -1;
    pg_parser->phase = NONE;
    pg_parser->c2s_way = UNSET;    // unset
    if (0 != streambuf_ctor(&pg_parser->sbuf, pg_sbuf_parse, 30000)) return -1;

    return 0;
}

static struct parser *pg_parser_new(struct proto *proto)
{
    struct pgsql_parser *pg_parser = objalloc_nice(sizeof(*pg_parser), "Pg parsers");
    if (! pg_parser) return NULL;

    if (-1 == pg_parser_ctor(pg_parser, proto)) {
        objfree(pg_parser);
        return NULL;
    }

    return &pg_parser->parser;
}

static void pg_parser_dtor(struct pgsql_parser *pg_parser)
{
    parser_dtor(&pg_parser->parser);
    streambuf_dtor(&pg_parser->sbuf);
}

static void pg_parser_del(struct parser *parser)
{
    struct pgsql_parser *pg_parser = DOWNCAST(parser, parser, pgsql_parser);
    pg_parser_dtor(pg_parser);
    objfree(pg_parser);
}

/*
 * Proto infos
 */

static char const *sql_ssl_2_str(enum sql_ssl ssl)
{
    switch (ssl) {
        case SQL_SSL_REQUESTED: return "SSL requested";
        case SQL_SSL_GRANTED:   return "SSL granted";
        case SQL_SSL_REFUSED:   return "SSL refused";
    }
    assert(!"Unknown sql_ssl");
    return "INVALID";
}

char const *sql_msg_type_2_str(enum sql_msg_type type)
{
    switch (type) {
        case SQL_UNKNOWN: return "unknown";
        case SQL_STARTUP: return "startup";
        case SQL_QUERY:   return "query";
        case SQL_EXIT:    return "exit";
    }
    assert(!"Unknown sql_msg_type");
    return "INVALID";
}

static char const *sql_request_status_2_str(enum sql_request_status status)
{
    switch (status) {
        case SQL_REQUEST_COMPLETE: return "Completed";
        case SQL_REQUEST_INCOMPLETE: return "Not completed";
        case SQL_REQUEST_ERROR: return "Error";
    }
    assert(!"Unknown sql_request_status");
    return "INVALID";
}

char const *sql_encoding_2_str(enum sql_encoding encoding)
{
    switch (encoding) {
        case SQL_ENCODING_UTF8: return "UTF8";
        case SQL_ENCODING_LATIN1: return "Latin1";
        case SQL_ENCODING_UNKNOWN: return "Unknown";
        default:
            assert(!"Unknown sql_encoding");
            return "INVALID";
    }
}

static char const *startup_query_2_str(struct sql_proto_info const *info)
{
    return tempstr_printf(", %s%s%s%s%s%s%s%s%s",
        info->set_values & SQL_SSL_REQUEST ? sql_ssl_2_str(info->u.startup.ssl_request) : "No SSL",
        info->set_values & SQL_USER   ? ", user=" : "",
        info->set_values & SQL_USER   ? info->u.startup.user : "",
        info->set_values & SQL_DBNAME ? ", dbname=" : "",
        info->set_values & SQL_DBNAME ? info->u.startup.dbname : "",
        info->set_values & SQL_PASSWD ? ", passwd=" : "",
        info->set_values & SQL_PASSWD ? info->u.startup.passwd : "",
        info->set_values & SQL_ENCODING ? ", encoding=" : "",
        info->set_values & SQL_ENCODING ? sql_encoding_2_str(info->u.startup.encoding) : ""
        );
}

// FIXME: a unsigned_if_set_2_str(info, set_mask, field_name, field_value) to replace various -1 for unset ints.
static char const *startup_reply_2_str(struct sql_proto_info const *info)
{
    return tempstr_printf(", %s%s%s",
        info->set_values & SQL_SSL_REQUEST ? sql_ssl_2_str(info->u.startup.ssl_request) : "No SSL",
        info->set_values & SQL_ENCODING ? ", encoding=" : "",
        info->set_values & SQL_ENCODING ? sql_encoding_2_str(info->u.startup.encoding) : "");
}

static char const *query_query_2_str(struct sql_proto_info const *info)
{
    return tempstr_printf("%s%s%s",
        info->set_values & SQL_SQL ? ", query='" : "",
        info->set_values & SQL_SQL ? info->u.query.sql : "",
        info->set_values & SQL_SQL ? "'" : "");
}

static char const *query_reply_2_str(struct sql_proto_info const *info)
{
    return tempstr_printf(", nb_rows=%d, nb_fields=%d",
        info->set_values & SQL_NB_ROWS   ? (int)info->u.query.nb_rows : -1,
        info->set_values & SQL_NB_FIELDS ? (int)info->u.query.nb_fields : -1);
}

static char const *exit_2_str(struct sql_proto_info const unused_ *info)
{
    return "";
}

static char const *version_info_2_str(struct sql_proto_info const *info)
{
    if (! (info->set_values & SQL_VERSION)) return "";
    return tempstr_printf(", version=%u.%u", info->version_maj, info->version_min);
}

char const *sql_info_2_str(struct proto_info const *info_)
{
    struct sql_proto_info const *info = DOWNCAST(info_, info, sql_proto_info);
    char *str = tempstr();

    char const *(*spec_info_2_str)(struct sql_proto_info const *) = NULL;
    switch (info->msg_type) {
        case SQL_UNKNOWN:
            break;
        case SQL_STARTUP:
            spec_info_2_str = info->is_query ? startup_query_2_str : startup_reply_2_str;
            break;
        case SQL_QUERY:
            spec_info_2_str = info->is_query ? query_query_2_str : query_reply_2_str;
            break;
        case SQL_EXIT:
            spec_info_2_str = exit_2_str;
            break;
    }

    snprintf(str, TEMPSTR_SIZE, "%s, %s%s, %s%s%s%s%s%s%s%s%s%s",
        proto_info_2_str(info_),
        info->is_query ? "Clt->Srv" : "Srv->Clt",
        version_info_2_str(info),
        sql_msg_type_2_str(info->msg_type),
        spec_info_2_str ? spec_info_2_str(info) : "",
        info->set_values & SQL_REQUEST_STATUS ? ", Status=" : "",
        info->set_values & SQL_REQUEST_STATUS ? sql_request_status_2_str(info->request_status) : "",
        info->set_values & SQL_ERROR_SQL_STATUS ? ", SqlCode=" : "",
        info->set_values & SQL_ERROR_SQL_STATUS ? info->error_sql_status : "",
        info->set_values & SQL_ERROR_CODE ? ", ErrorCode=" : "",
        info->set_values & SQL_ERROR_CODE ? info->error_code : "",
        info->set_values & SQL_ERROR_MESSAGE ? ", ErrorMessage=" : "",
        info->set_values & SQL_ERROR_MESSAGE ? info->error_message : "");
    return str;
}

void const *sql_info_addr(struct proto_info const *info_, size_t *size)
{
    struct sql_proto_info const *info = DOWNCAST(info_, info, sql_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

// Set both the query and the flag that indicate if the query was truncated.
int sql_set_query(struct sql_proto_info *info, char const *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int size = vsnprintf(info->u.query.sql, sizeof(info->u.query.sql), fmt, args);
    va_end(args);
    if (size >= 0) {
        info->set_values |= SQL_SQL;
        info->u.query.truncated = ((unsigned)size >= sizeof(info->u.query.sql));
    }
    return size;
}

/*
 * Parse
 */

static enum proto_parse_status pg_parse_error(struct sql_proto_info *info, struct cursor *cursor, size_t len)
{
    enum proto_parse_status status;
    info->set_values |= SQL_REQUEST_STATUS;
    info->request_status = SQL_REQUEST_ERROR;

    size_t size = 0;
    char *str;

    while (size <= len) {
        size++;
        if (size > len) return PROTO_PARSE_ERR;
        char type = cursor_read_u8(cursor);
        if (type == 0x00) {
            break;
        }
        status = cursor_read_string(cursor, &str, len - size);
        if (status != PROTO_OK) return status;
        size += strlen(str) + 1;
        switch (type) {
            case 'C':
                info->set_values |= SQL_ERROR_SQL_STATUS;
                snprintf(info->error_sql_status, sizeof(info->error_sql_status), "%s", str);
                break;
            case 'M':
                info->set_values |= SQL_ERROR_MESSAGE;
                snprintf(info->error_message, sizeof(info->error_message), "%s", str);
                break;
        }
    }
    return PROTO_OK;
}

/* Read a message header, return type and msg length, and advance the cursor to the msg payload.
 * if type is NULL that means no type are read from the cursor.
 * return PROTO_TOO_SHORT if the msg content is not available. */
static enum proto_parse_status cursor_read_msg(struct cursor *cursor, uint8_t *type, size_t *len_)
{
    SLOG(LOG_DEBUG, "Reading new message");
    unsigned rollback = 0;

    if (type) { // read type first
        CHECK_LEN(cursor, 1, rollback);
        *type = cursor_read_u8(cursor);
        rollback++;
        SLOG(LOG_DEBUG, "... of type %u ('%c')", (unsigned)*type, *type);
    }

    // read length
    CHECK_LEN(cursor, 4, rollback);
    size_t len = cursor_read_u32n(cursor);
    rollback += 4;
    if (len < 4) return PROTO_PARSE_ERR;    // as length includes itself
    len -= 4;
    SLOG(LOG_DEBUG, "... of length %zu", len);

    if (len_) *len_ = len;

    // read payload
    CHECK_LEN(cursor, len, rollback);

    return PROTO_OK;
}

static void pg_parse_client_encoding(struct sql_proto_info *info, char const *value)
{
    SLOG(LOG_DEBUG, "Parse sql encoding %s", value);
    info->set_values |= SQL_ENCODING;
    if (0 == strcmp(value, "UTF8")) {
        info->u.startup.encoding = SQL_ENCODING_UTF8;
    } else if (0 == strcmp(value, "LATIN1")) {
        info->u.startup.encoding = SQL_ENCODING_LATIN1;
    } else {
        SLOG(LOG_DEBUG, "Unknown client encoding (%s)", value);
        info->u.startup.encoding = SQL_ENCODING_UNKNOWN;
    }
}

static enum proto_parse_status pg_parse_parameter_value(struct cursor *cursor, char **name, char **value, size_t len)
{
    enum proto_parse_status status = cursor_read_string(cursor, name, len);
    if (status != PROTO_OK) return status;
    if (name[0] == '\0') return PROTO_OK;
    return cursor_read_string(cursor, value, len );
}

static enum proto_parse_status pg_parse_init(struct pgsql_parser *pg_parser, struct sql_proto_info *info, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    info->msg_type = SQL_STARTUP;

    /* NONE phase is when we haven't seen the startup message yet.
     * In this phase, we expect to see from the client a startup message,
     * and from the server nothing but an answer to an SSL request. */
    if (info->is_query) {
        struct cursor cursor;
        cursor_ctor(&cursor, payload, cap_len);

        // Startup message comes without a type tag
        size_t len;
        enum proto_parse_status status = cursor_read_msg(&cursor, NULL, &len);
        if (status != PROTO_OK) return status;
        SLOG(LOG_DEBUG, "Msg of length %zu", len);
        if (len < 4) return PROTO_PARSE_ERR;
        uint32_t msg = cursor_read_u32n(&cursor);
        if (msg == 80877103) {  // magic value for SSL request
            SLOG(LOG_DEBUG, "Msg is an SSL request");
            info->set_values |= SQL_SSL_REQUEST;
            info->u.startup.ssl_request = SQL_SSL_REQUESTED;
        } else if (msg == 196608) { // version number, here 00 03 00 00 (ie. 3.0), which is parsed here
            SLOG(LOG_DEBUG, "Msg is a startup message for v3.0");
            info->version_maj = 3;
            info->version_min = 0;
            info->set_values |= SQL_VERSION;
            // fine, now parse all the strings that follow
            do {
                char *name, *value;
                status = pg_parse_parameter_value(&cursor, &name, &value, len);
                if (name[0] == '\0') break;
                if (status != PROTO_OK) return status;

                if (0 == strcmp(name, "user")) {
                    info->set_values |= SQL_USER;
                    snprintf(info->u.startup.user, sizeof(info->u.startup.user), "%s", value);
                } else if (0 == strcmp(name, "database")) {
                    info->set_values |= SQL_DBNAME;
                    snprintf(info->u.startup.dbname, sizeof(info->u.startup.dbname), "%s", value);
                } else if (0 == strcmp(name, "client_encoding")) {
                    pg_parse_client_encoding(info, value);
                }

            } while (1);
            // and enter "startup phase" untill the server is ready for query
            pg_parser->phase = STARTUP;
        } else {
            SLOG(LOG_DEBUG, "Unknown message");
            return PROTO_PARSE_ERR;
        }
    } else {    // reply (to an SSL request)
        if (wire_len != 1 || cap_len < 1) return PROTO_TOO_SHORT;
        info->set_values |= SQL_SSL_REQUEST;
        if (payload[0] == 'S') {
            info->u.startup.ssl_request = SQL_SSL_GRANTED;  // We will get parse errors from now on :-<
        } else if (payload[0] == 'N') {
            info->u.startup.ssl_request = SQL_SSL_REFUSED;
        } else {
            return PROTO_PARSE_ERR;
        }
    }

    return proto_parse(NULL, &info->info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
}

static enum proto_parse_status pg_parse_parameter_status(struct sql_proto_info *info, struct cursor *cursor)
{
    SLOG(LOG_DEBUG, "Parse of parameters stats");
    do {
        uint8_t type;
        size_t len;
        enum proto_parse_status status = cursor_read_msg(cursor, &type, &len);
        if (status != PROTO_OK) return status;
        if (type != 'S') {
            // Finished parse of parameter status
            return PROTO_OK;
        }
        char *name, *value;
        status = pg_parse_parameter_value(cursor, &name, &value, len);
        if (0 == strcmp(name, "client_encoding")) {
            pg_parse_client_encoding(info, value);
            // We only care of client encoding for now
            return PROTO_OK;
        }
    } while(1);
}

static enum proto_parse_status pg_parse_startup(struct pgsql_parser *pg_parser, struct sql_proto_info *info, unsigned way, uint8_t const *payload, size_t cap_len, size_t unused_ wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    info->msg_type = SQL_STARTUP;

    struct cursor cursor;
    cursor_ctor(&cursor, payload, cap_len);
    uint8_t type;
    size_t len;
    enum proto_parse_status status = cursor_read_msg(&cursor, &type, &len);
    if (status != PROTO_OK) return status;

    /* In this phase, we expect to see from the client the pwd message,
     * and from the server the authentication request. */
    if (info->is_query) {   // password message
        if (type != 'p') return PROTO_PARSE_ERR;
        char *passwd;
        status = cursor_read_string(&cursor, &passwd, len);
        if (status == PROTO_PARSE_ERR) return status;
        if (status == PROTO_TOO_SHORT) {    // in case of GSSAPI or SSPI authentication then the "string" is in fact arbitrary bytes
            passwd = "GSSAPI/SSPI";
        }
        info->set_values |= SQL_PASSWD;
        snprintf(info->u.startup.passwd, sizeof(info->u.startup.passwd), "%s", passwd);
    } else {    // Authentication request
        SLOG(LOG_DEBUG, "Authentification response from server with type %c", type);
        if (len < 4) return PROTO_PARSE_ERR;
        if (type == 'E') {
            status = pg_parse_error(info, &cursor, len);
            if (status != PROTO_OK) return status;
        } else if (type == 'R' ) {
            // We don't care about the auth method, we just want to know when auth is complete
            uint32_t auth_type = cursor_read_u32n(&cursor);
            if (auth_type == 0) {   // AuthenticationOK
                pg_parser->phase = QUERY;   // we don't wait for the ReadyForQuery msg since we are not interrested in following messages
                info->set_values |= SQL_REQUEST_STATUS;
                info->request_status = SQL_REQUEST_COMPLETE;
            }
            pg_parse_parameter_status(info, &cursor);
        } else {
            SLOG(LOG_DEBUG, "Unknown startup message with type %c", type);
            return PROTO_PARSE_ERR;
        }
    }

    // Discard the rest of the packet
    return proto_parse(NULL, &info->info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
}

// nb_rows is always the last word of result
static enum proto_parse_status fetch_nb_rows(char const *result, unsigned *nb_rows)
{
    SLOG(LOG_DEBUG, "Looking for nb_rows in '%s'", result);

    char const *last_space = NULL;
    for (char const *c = result; *c != '\0'; c++) {
        if (*c == ' ') last_space = c;
    }

    if (! last_space) return PROTO_PARSE_ERR;

    char *end;
    *nb_rows = strtoul(last_space+1, &end, 10);
    if (*end != '\0') return PROTO_PARSE_ERR;

    SLOG(LOG_DEBUG, "Fetching nb_rows = %u", *nb_rows);
    return PROTO_OK;
}

static enum proto_parse_status pg_parse_query(struct pgsql_parser *pg_parser, struct sql_proto_info *info, unsigned way, uint8_t const *payload, size_t cap_len, size_t unused_ wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    enum proto_parse_status status;
    info->msg_type = SQL_QUERY;

    struct cursor cursor;
    cursor_ctor(&cursor, payload, cap_len);
    uint8_t type;
    size_t len;

    /* In this phase, we are looking for SimpleQuery from the client and Data from the server.
     * This is very simplistic, to be completed later with more interesting query types.
     * Also, the client can send a termination request. */
    if (info->is_query) {
        status = cursor_read_msg(&cursor, &type, &len);
        if (status != PROTO_OK) return status;

        if (type == 'Q') {  // simple query
            char *sql;
            status = cursor_read_string(&cursor, &sql, len);
            if (status != PROTO_OK) return status;
            sql_set_query(info, "%s", sql);
        } else if (type == 'X') {
            info->msg_type = SQL_EXIT;
            info->set_values |= SQL_REQUEST_STATUS;
            info->request_status = SQL_REQUEST_COMPLETE;
            pg_parser->phase = EXIT;
        } else return PROTO_PARSE_ERR;
    } else {
        while (! cursor_is_empty(&cursor)) {
            uint8_t const *const msg_start = cursor.head;
            status = cursor_read_msg(&cursor, &type, &len);
            if (status == PROTO_PARSE_ERR) return status;
            else if (status == PROTO_TOO_SHORT) {
                SLOG(LOG_DEBUG, "Payload too short for parsing message, will restart");
                status = proto_parse(NULL, &info->info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);    // ack what we had so far
                streambuf_set_restart(&pg_parser->sbuf, way, msg_start, true);
                return PROTO_OK;
            }

            uint8_t const *const msg_end = cursor.head + len;
            if (type == 'T') {  // row description (fetch nb_fields)
                if (len < 2) return PROTO_PARSE_ERR;
                info->u.query.nb_fields = cursor_read_u16n(&cursor);
                info->set_values |= SQL_NB_FIELDS;
                SLOG(LOG_DEBUG, "Setting nb_fields to %u", info->u.query.nb_fields);
            } else if (type == 'D') {   // data row
                if (len < 2) return PROTO_PARSE_ERR;
                if (! (info->set_values & SQL_NB_ROWS)) {
                    info->set_values |= SQL_NB_ROWS;
                    info->u.query.nb_rows = 0;
                }
                info->u.query.nb_rows ++;
                SLOG(LOG_DEBUG, "Incrementing nb_rows (now %u)", info->u.query.nb_rows);
            } else if (type == 'C') {   // command complete (fetch nb rows)
                char *result;
                info->set_values |= SQL_REQUEST_STATUS;
                info->request_status = SQL_REQUEST_COMPLETE;
                status = cursor_read_string(&cursor, &result, len);
                if (status != PROTO_OK) return status;
                status = fetch_nb_rows(result, &info->u.query.nb_rows);
                if (status == PROTO_OK) {
                    info->set_values |= SQL_NB_ROWS;
                } else {
                    //return status;    // Do not use this as the actual protocol does not seam to implement the doc :-<
                }
            } else if (type == 'E') {   // error
                status = pg_parse_error(info, &cursor, len);
                if (status != PROTO_OK) return status;
            }
            // Skip what's left of this message and go for the next
            assert(msg_end >= cursor.head);
            cursor_drop(&cursor, msg_end - cursor.head);
        }
    }

    return proto_parse(NULL, &info->info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
}

static enum proto_parse_status pg_sbuf_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct pgsql_parser *pg_parser = DOWNCAST(parser, parser, pgsql_parser);

    // If this is the first time we are called, init c2s_way
    if (pg_parser->c2s_way == UNSET) {
        SLOG(LOG_DEBUG, "First packet, init c2s_way to %u", way);
        pg_parser->c2s_way = way;
    }

    // Now build the proto_info
    struct sql_proto_info info;
    proto_info_ctor(&info.info, parser, parent, wire_len, 0);
    info.is_query = way == pg_parser->c2s_way;
    info.set_values = 0;

    switch (pg_parser->phase) {
        case NONE:    return pg_parse_init   (pg_parser, &info, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);
        case STARTUP: return pg_parse_startup(pg_parser, &info, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);
        case QUERY:   return pg_parse_query  (pg_parser, &info, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);
        case EXIT:    return PROTO_PARSE_ERR;   // we do not expect payload after a termination message
    }

    return PROTO_PARSE_ERR;
}

static enum proto_parse_status pg_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct pgsql_parser *pg_parser = DOWNCAST(parser, parser, pgsql_parser);

    enum proto_parse_status const status = streambuf_add(&pg_parser->sbuf, parser, parent, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);

    return status;
}

/*
 * Construction/Destruction
 */

static struct proto proto_pgsql_;
struct proto *proto_pgsql = &proto_pgsql_;
static struct port_muxer pg_tcp_muxer;

void pgsql_init(void)
{
    log_category_proto_pgsql_init();

    static struct proto_ops const ops = {
        .parse       = pg_parse,
        .parser_new  = pg_parser_new,
        .parser_del  = pg_parser_del,
        .info_2_str  = sql_info_2_str,
        .info_addr   = sql_info_addr
    };
    proto_ctor(&proto_pgsql_, &ops, "PostgreSQL", PROTO_CODE_PGSQL);
    port_muxer_ctor(&pg_tcp_muxer, &tcp_port_muxers, 5432, 5432, proto_pgsql);
}

void pgsql_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    port_muxer_dtor(&pg_tcp_muxer, &tcp_port_muxers);
    proto_dtor(&proto_pgsql_);
#   endif
    log_category_proto_pgsql_fini();
}
