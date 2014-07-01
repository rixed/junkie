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

enum pgsql_msg_type {
    // Backend
    PGSQL_AUTHENTIFICATION = 'R',
    PGSQL_BACKEND_KEY = 'K',
    PGSQL_BIND_COMPLETE = '2',
    PGSQL_COMMAND_COMPLETE = 'C',
    PGSQL_CLOSE_COMPLETE = '3',
    PGSQL_COPY_IN_RESPONSE = 'G',
    PGSQL_COPY_OUT_RESPONSE = 'H',
    PGSQL_COPY_BOTH_RESPONSE = 'W',
    PGSQL_DATA_ROW = 'D',
    PGSQL_EMPTY_QUERY_RESPONSE = 'I',
    PGSQL_ERROR_RESPONSE = 'E',
    PGSQL_FUNCTION_CALL_RESPONSE = 'V',
    PGSQL_NO_DATA = 'n',
    PGSQL_NOTICE_RESPONSE = 'N',
    PGSQL_NOTIFICATION_RESPONSE = 'A',
    PGSQL_PARAMETER_DESCRIPTION = 't',
    PGSQL_PARAMETER_STATUS = 'S',
    PGSQL_PARSE_COMPLETE = '1',
    PGSQL_PORTAL_SUSPENDED = 's',
    PGSQL_READY_FOR_QUERY = 'Z',
    PGSQL_ROW_DESCRIPTION = 'T',
    // Frontend
    PGSQL_BIND = 'B',
    PGSQL_CLOSE = 'C',
    PGSQL_COPY_FAIL = 'f',
    PGSQL_DESCRIBE = 'D',
    PGSQL_EXECUTE = 'E',
    PGSQL_FLUSH = 'H',
    PGSQL_FUNCTION_CALL = 'F',
    PGSQL_PARSE = 'P',
    PGSQL_PASSWORD_MESSAGE = 'p',
    PGSQL_QUERY = 'Q',
    PGSQL_SYNC = 'S',
    PGSQL_TERMINATE = 'X',
    // Both
    PGSQL_COPY_DATA = 'd',
    PGSQL_COPY_DONE = 'c',
};

static char const *pgsql_msg_type_2_str(enum pgsql_msg_type type, bool is_query)
{
    if (is_query) {
        switch(type) {
            case PGSQL_BIND: return "PGSQL_BIND";
            case PGSQL_CLOSE: return "PGSQL_CLOSE";
            case PGSQL_COPY_FAIL: return "PGSQL_COPY_FAIL";
            case PGSQL_DESCRIBE: return "PGSQL_DESCRIBE";
            case PGSQL_EXECUTE: return "PGSQL_EXECUTE";
            case PGSQL_FLUSH: return "PGSQL_FLUSH";
            case PGSQL_FUNCTION_CALL: return "PGSQL_FUNCTION_CALL";
            case PGSQL_PARSE: return "PGSQL_PARSE";
            case PGSQL_PASSWORD_MESSAGE: return "PGSQL_PASSWORD_MESSAGE";
            case PGSQL_QUERY: return "PGSQL_QUERY";
            case PGSQL_SYNC: return "PGSQL_SYNC";
            case PGSQL_TERMINATE: return "PGSQL_TERMINATE";
            case PGSQL_COPY_DATA: return "PGSQL_COPY_DATA";
            case PGSQL_COPY_DONE: return "PGSQL_COPY_DONE";
            default:
                break;
        }
    } else {
        switch (type) {
            case PGSQL_AUTHENTIFICATION: return "PGSQL_AUTHENTIFICATION";
            case PGSQL_BACKEND_KEY: return "PGSQL_BACKEND_KEY";
            case PGSQL_BIND_COMPLETE: return "PGSQL_BIND_COMPLETE";
            case PGSQL_COMMAND_COMPLETE: return "PGSQL_COMMAND_COMPLETE";
            case PGSQL_CLOSE_COMPLETE: return "PGSQL_CLOSE_COMPLETE";
            case PGSQL_COPY_IN_RESPONSE: return "PGSQL_COPY_IN_RESPONSE";
            case PGSQL_COPY_OUT_RESPONSE: return "PGSQL_COPY_OUT_RESPONSE";
            case PGSQL_COPY_BOTH_RESPONSE: return "PGSQL_COPY_BOTH_RESPONSE";
            case PGSQL_DATA_ROW: return "PGSQL_DATA_ROW";
            case PGSQL_EMPTY_QUERY_RESPONSE: return "PGSQL_EMPTY_QUERY_RESPONSE";
            case PGSQL_ERROR_RESPONSE: return "PGSQL_ERROR_RESPONSE";
            case PGSQL_FUNCTION_CALL_RESPONSE: return "PGSQL_FUNCTION_CALL_RESPONSE";
            case PGSQL_NO_DATA: return "PGSQL_NO_DATA";
            case PGSQL_NOTICE_RESPONSE: return "PGSQL_NOTICE_RESPONSE";
            case PGSQL_NOTIFICATION_RESPONSE: return "PGSQL_NOTIFICATION_RESPONSE";
            case PGSQL_PARAMETER_DESCRIPTION: return "PGSQL_PARAMETER_DESCRIPTION";
            case PGSQL_PARAMETER_STATUS: return "PGSQL_PARAMETER_STATUS";
            case PGSQL_PARSE_COMPLETE: return "PGSQL_PARSE_COMPLETE";
            case PGSQL_PORTAL_SUSPENDED: return "PGSQL_PORTAL_SUSPENDED";
            case PGSQL_READY_FOR_QUERY: return "PGSQL_READY_FOR_QUERY";
            case PGSQL_ROW_DESCRIPTION: return "PGSQL_ROW_DESCRIPTION";
            case PGSQL_COPY_DATA: return "PGSQL_COPY_DATA";
            case PGSQL_COPY_DONE: return "PGSQL_COPY_DONE";
            default:
                break;
        }
    }
    return tempstr_printf("unknown (%u)", type);
}

struct pgsql_header {
    enum pgsql_msg_type type;
    size_t length;
};

struct pgsql_parser {
    struct parser parser;
    unsigned c2s_way;       // The way when traffic is going from client to server (UNSET for unset)
    enum phase { NONE, STARTUP, QUERY, EXIT } phase;
    struct streambuf sbuf;
};

static char const *pgsql_phase_2_str(enum phase phase)
{
    switch (phase) {
        case NONE    : return "NONE";
        case STARTUP : return "STARTUP";
        case QUERY   : return "QUERY";
        case EXIT    : return "EXIT";
        default      : return tempstr_printf("Unknown (%u)", phase);
    }
}

static parse_fun pg_sbuf_parse;

static int pg_parser_ctor(struct pgsql_parser *pg_parser, struct proto *proto)
{
    assert(proto == proto_pgsql);
    if (0 != parser_ctor(&pg_parser->parser, proto)) return -1;
    pg_parser->phase = NONE;
    pg_parser->c2s_way = UNSET;    // unset
    if (0 != streambuf_ctor(&pg_parser->sbuf, pg_sbuf_parse, 30000, NULL)) return -1;

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
 * Parse
 */

static enum proto_parse_status pg_parse_error(struct sql_proto_info *info, struct cursor *cursor, size_t len)
{
    enum proto_parse_status status;
    sql_set_request_status(info, SQL_REQUEST_ERROR);

    size_t size = 0;
    char *str;

    while (size <= len) {
        size++;
        if (size > len) return PROTO_PARSE_ERR;
        char type = cursor_read_u8(cursor);
        if (type == 0x00) {
            break;
        }
        size_t read_len;
        status = cursor_read_string(cursor, &str, &read_len, len - size);
        if (status != PROTO_OK) return status;
        size += read_len + 1;
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
 * return PROTO_TOO_SHORT if the msg content is not available. */
static enum proto_parse_status cursor_read_msg(struct cursor *cursor, struct pgsql_header *header, bool is_query)
{
    assert(header);
    SLOG(LOG_DEBUG, "Reading new message");

    CHECK(1);
    header->type = cursor_read_u8(cursor);
    SLOG(LOG_DEBUG, "... of type %s (0x%02x '%c')", pgsql_msg_type_2_str(header->type, is_query),
            (unsigned)header->type, header->type);
    // read length
    CHECK(4);
    header->length = cursor_read_u32n(cursor);
    if (header->length < 4) return PROTO_PARSE_ERR;    // as length includes itself
    header->length -= 4;
    SLOG(LOG_DEBUG, "... of length %zu", header->length);

    // read payload
    CHECK(header->length);
    return PROTO_OK;
}

static void pg_parse_client_encoding(struct sql_proto_info *info, char const *value)
{
    SLOG(LOG_DEBUG, "Parse sql encoding %s", value);
    if (0 == strcmp(value, "UTF8")) {
        sql_set_encoding(info, SQL_ENCODING_UTF8);
    } else if (0 == strcmp(value, "LATIN1")) {
        sql_set_encoding(info, SQL_ENCODING_LATIN1);
    } else if (0 == strcmp(value, "LATIN9")) {
        sql_set_encoding(info, SQL_ENCODING_LATIN9);
    } else {
        SLOG(LOG_DEBUG, "Unknown client encoding (%s)", value);
        sql_set_encoding(info, SQL_ENCODING_UNKNOWN);
    }
}

static enum proto_parse_status pg_parse_parameter_value(struct cursor *cursor, char **out_name, char **out_value, size_t *out_len, size_t left_size)
{
    size_t read_len = 0;
    enum proto_parse_status status = cursor_read_string(cursor, out_name, &read_len, left_size);
    if (status != PROTO_OK) return status;
    if (out_len) *out_len = read_len;
    if (read_len == 0) return PROTO_OK;

    left_size -= read_len;
    status = cursor_read_string(cursor, out_value, &read_len, left_size);
    if (out_len) *out_len += read_len;
    return status;
}

/*
 * SSL request:
 * | 4 bytes                         | 4 bytes              |
 * | Length message (including self) | SSL request 80877103 |
 *
 * Startup message:
 * | 4 bytes                         | 4 bytes                        | string                                    | string           |
 * | Length message (including self) | Protocol version number 196608 | parameters name (user, database, options) | parameters value |
 */
static enum proto_parse_status pg_parse_init_phase(struct pgsql_parser *pg_parser, struct sql_proto_info *info, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    enum proto_parse_status status;
    info->msg_type = SQL_STARTUP;

    /* NONE phase is when we haven't seen the startup message yet.
     * In this phase, we expect to see from the client a startup message,
     * and from the server nothing but an answer to an SSL request. */
    if (info->is_query) {
        struct cursor cursor;
        cursor_ctor(&cursor, payload, cap_len);

        // Startup message starts with the length
        CHECK_LEN(&cursor, 8, 0);
        size_t len = cursor_read_u32n(&cursor);

        SLOG(LOG_DEBUG, "Msg of length %zu", len);
        if (len < 8) return PROTO_PARSE_ERR;
        size_t left_size = len - 8;;
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
                size_t read_len = 0;
                status = pg_parse_parameter_value(&cursor, &name, &value, &read_len, left_size);
                if (status != PROTO_OK) return status;
                if (read_len == 0) break;
                left_size -= read_len;

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
        if (payload[0] == PGSQL_PARAMETER_STATUS) {
            info->u.startup.ssl_request = SQL_SSL_GRANTED;  // We will get parse errors from now on :-<
        } else if (payload[0] == PGSQL_NOTICE_RESPONSE) {
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
    while (1) {
        struct pgsql_header header;
        enum proto_parse_status status = cursor_read_msg(cursor, &header, info->is_query);
        if (status != PROTO_OK) return status;
        if (header.type != PGSQL_PARAMETER_STATUS) {
            // Finished parse of parameter status
            return PROTO_OK;
        }
        char *name, *value;
        status = pg_parse_parameter_value(cursor, &name, &value, NULL, header.length);
        if (status != PROTO_OK) return status;
        if (0 == strcmp(name, "client_encoding")) {
            pg_parse_client_encoding(info, value);
            // We only care of client encoding for now
            return PROTO_OK;
        }
    }
}

static enum proto_parse_status pg_parse_startup_phase(struct pgsql_parser *pg_parser, struct sql_proto_info *info, unsigned way, uint8_t const *payload, size_t cap_len, size_t unused_ wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    info->msg_type = SQL_STARTUP;

    struct cursor cursor;
    cursor_ctor(&cursor, payload, cap_len);
    struct pgsql_header header;
    enum proto_parse_status status = cursor_read_msg(&cursor, &header, info->is_query);
    if (status != PROTO_OK) return status;

    /* In this phase, we expect to see from the client the pwd message,
     * and from the server the authentication request. */
    if (info->is_query) {   // password message
        if (header.type != PGSQL_PASSWORD_MESSAGE) return PROTO_PARSE_ERR;
        char *passwd;
        status = cursor_read_string(&cursor, &passwd, NULL, header.length);
        if (status == PROTO_PARSE_ERR) return status;
        if (status == PROTO_TOO_SHORT) {    // in case of GSSAPI or SSPI authentication then the "string" is in fact arbitrary bytes
            passwd = "GSSAPI/SSPI";
        }
        info->set_values |= SQL_PASSWD;
        snprintf(info->u.startup.passwd, sizeof(info->u.startup.passwd), "%s", passwd);
    } else {    // Authentication request
        SLOG(LOG_DEBUG, "Authentification response from server with type %c", header.type);
        if (header.length < 4) return PROTO_PARSE_ERR;
        if (header.type == PGSQL_ERROR_RESPONSE) {
            status = pg_parse_error(info, &cursor, header.length);
            if (status != PROTO_OK) return status;
        } else if (header.type == PGSQL_AUTHENTIFICATION ) {
            // We don't care about the auth method, we just want to know when auth is complete
            uint32_t auth_type = cursor_read_u32n(&cursor);
            // Drop the rest of authentication request
            cursor_drop(&cursor, header.length - 4);
            if (auth_type == 0) {   // AuthenticationOK
                pg_parser->phase = QUERY;   // we don't wait for the ReadyForQuery msg since we are not interrested in following messages
                sql_set_request_status(info, SQL_REQUEST_COMPLETE);
                pg_parse_parameter_status(info, &cursor);
            }
        } else {
            SLOG(LOG_DEBUG, "Unknown startup message with type %c", header.type);
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

static void is_query_type(uint8_t type, bool *is_query)
{
    switch (type) {
    case PGSQL_AUTHENTIFICATION:
    case PGSQL_BACKEND_KEY:
    case PGSQL_BIND_COMPLETE:
    case PGSQL_CLOSE_COMPLETE:
    case PGSQL_COPY_IN_RESPONSE:
    case PGSQL_COPY_BOTH_RESPONSE:
    case PGSQL_EMPTY_QUERY_RESPONSE:
    case PGSQL_FUNCTION_CALL_RESPONSE:
    case PGSQL_NO_DATA:
    case PGSQL_NOTICE_RESPONSE:
    case PGSQL_NOTIFICATION_RESPONSE:
    case PGSQL_PARAMETER_DESCRIPTION:
    case PGSQL_PARSE_COMPLETE:
    case PGSQL_PORTAL_SUSPENDED:
    case PGSQL_READY_FOR_QUERY:
    case PGSQL_ROW_DESCRIPTION:
        *is_query = false;
        break;
    case PGSQL_BIND:
    case PGSQL_COPY_FAIL:
    case PGSQL_FUNCTION_CALL:
    case PGSQL_PARSE:
    case PGSQL_PASSWORD_MESSAGE:
    case PGSQL_QUERY:
    case PGSQL_TERMINATE:
        *is_query = true;
        break;
    default:
        break;
    }
}

static enum proto_parse_status pg_parse_query_client(struct pgsql_parser *pg_parser, struct cursor *cursor,
        struct sql_proto_info *info, struct pgsql_header *header)
{
    SLOG(LOG_DEBUG, "Parse a query from client");
    enum proto_parse_status status;

    /* In this phase, we are looking for SimpleQuery from the client and Data from the server.
     * This is very simplistic, to be completed later with more interesting query types.
     * Also, the client can send a termination request. */
    while (! cursor_is_empty(cursor)) {
        uint8_t const *const msg_start = cursor->head;
        status = cursor_read_msg(cursor, header, info->is_query);
        if (status == PROTO_TOO_SHORT) {
            cursor_rollback(cursor, cursor->head - msg_start);
        }
        if (status != PROTO_OK) return status;
        switch(header->type) {
            case PGSQL_QUERY:
                {
                    char *sql;
                    status = cursor_read_string(cursor, &sql, NULL, header->length);
                    if (status != PROTO_OK) return status;
                    sql_set_query(info, "%s", sql);
                }
                break;
            case PGSQL_PARSE:
                {
                    uint8_t const *const msg_end = cursor->head + header->length;
                    size_t read_len;
                    // Skip statement
                    if (PROTO_OK != (status = cursor_read_string(cursor, NULL, &read_len, header->length)))
                        return status;
                    char *sql;
                    if (PROTO_OK != (status = cursor_read_string(cursor, &sql, NULL, header->length - read_len)))
                        return status;
                    sql_set_query(info, "%s", sql);
                    cursor_drop(cursor, msg_end - cursor->head);
                }
                break;
            case PGSQL_TERMINATE:
                {
                    info->msg_type = SQL_EXIT;
                    sql_set_request_status(info, SQL_REQUEST_COMPLETE);
                    pg_parser->phase = EXIT;
                }
                break;
            default:
                // Just drop
                cursor_drop(cursor, header->length);
        }
    }
    return status;
}

static enum proto_parse_status pg_parse_query_server(struct cursor *cursor, struct sql_proto_info *info, struct pgsql_header *header)
{
    SLOG(LOG_DEBUG, "Parse a query response from server");
    enum proto_parse_status status;
    while (! cursor_is_empty(cursor)) {
        uint8_t const *const msg_start = cursor->head;
        status = cursor_read_msg(cursor, header, info->is_query);
        if (status == PROTO_TOO_SHORT) {
            cursor_rollback(cursor, cursor->head - msg_start);
        }
        if (status != PROTO_OK) return status;

        uint8_t const *const msg_end = cursor->head + header->length;
        switch (header->type) {
            // row description (fetch nb_fields)
            case PGSQL_ROW_DESCRIPTION:
                {
                    if (header->length < 2) return PROTO_PARSE_ERR;
                    uint_least16_t field_count = cursor_read_u16n(cursor);
                    sql_set_field_count(info, field_count );
                    SLOG(LOG_DEBUG, "Setting nb_fields to %u", info->u.query.nb_fields);
                }
                break;
            case PGSQL_DATA_ROW:
                {
                    if (header->length < 2) return PROTO_PARSE_ERR;
                    sql_increment_row_count(info, 1);
                    SLOG(LOG_DEBUG, "Incrementing nb_rows (now %u)", info->u.query.nb_rows);
                }
                break;
                // command complete (fetch nb rows)
            case PGSQL_COMMAND_COMPLETE:
                {
                    char *result;
                    sql_set_request_status(info, SQL_REQUEST_COMPLETE);
                    status = cursor_read_string(cursor, &result, NULL, header->length);
                    if (status != PROTO_OK) return status;
                    status = fetch_nb_rows(result, &info->u.query.nb_rows);
                    if (status == PROTO_OK) {
                        info->set_values |= SQL_NB_ROWS;
                    } else {
                        //return status;    // Do not use this as the actual protocol does not seam to implement the doc :-<
                    }
                }
                break;
            case PGSQL_ERROR_RESPONSE:
                {
                    status = pg_parse_error(info, cursor, header->length);
                    if (status != PROTO_OK) return status;
                }
                break;
            default:
                break;
        }
        // Skip what's left of this message and go for the next
        assert(msg_end >= cursor->head);
        cursor_drop(cursor, msg_end - cursor->head);
    }
    return PROTO_OK;
}

static enum proto_parse_status pg_parse_query_phase(struct pgsql_parser *pg_parser, struct sql_proto_info *info, unsigned way, uint8_t const *payload, size_t cap_len, size_t unused_ wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    enum proto_parse_status status;
    info->msg_type = SQL_QUERY;

    struct cursor cursor;
    cursor_ctor(&cursor, payload, cap_len);

    struct pgsql_header header;
    if (info->is_query) {
        status = pg_parse_query_client(pg_parser, &cursor, info, &header);
    } else {
        status = pg_parse_query_server(&cursor, info, &header);
    }
    if (status == PROTO_TOO_SHORT) {
        SLOG(LOG_DEBUG, "Payload too short for parsing message, will restart");
        status = proto_parse(NULL, &info->info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);    // ack what we had so far
        streambuf_set_restart(&pg_parser->sbuf, way, cursor.head, true);
        return PROTO_OK;
    }

    SLOG(LOG_DEBUG, "Query parsed with status %s", proto_parse_status_2_str(status));
    if (status != PROTO_OK) return status;
    return proto_parse(NULL, &info->info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
}

static enum phase guess_phase(uint8_t msg_type)
{
    switch(msg_type) {
        // init types (srv->clt)
        case PGSQL_NOTICE_RESPONSE:
        case PGSQL_PARAMETER_STATUS:
            return NONE;
        // Query types
        case PGSQL_BACKEND_KEY:
        case PGSQL_BIND_COMPLETE:
        case PGSQL_COMMAND_COMPLETE:
        case PGSQL_CLOSE_COMPLETE:
        case PGSQL_COPY_IN_RESPONSE:
        case PGSQL_COPY_OUT_RESPONSE:
        case PGSQL_COPY_BOTH_RESPONSE:
        case PGSQL_DATA_ROW:
        case PGSQL_EMPTY_QUERY_RESPONSE:
        case PGSQL_FUNCTION_CALL_RESPONSE:
        case PGSQL_NO_DATA:
        case PGSQL_NOTIFICATION_RESPONSE:
        case PGSQL_PARAMETER_DESCRIPTION:
        case PGSQL_PARSE_COMPLETE:
        case PGSQL_PORTAL_SUSPENDED:
        case PGSQL_READY_FOR_QUERY:
        case PGSQL_ROW_DESCRIPTION:
        case PGSQL_BIND:
        case PGSQL_COPY_FAIL:
        case PGSQL_FUNCTION_CALL:
        case PGSQL_PARSE:
        case PGSQL_QUERY:
        case PGSQL_TERMINATE:
        case PGSQL_COPY_DATA:
        case PGSQL_COPY_DONE:
            return QUERY;
        // Startup types
        // (clt->srv)
        case PGSQL_PASSWORD_MESSAGE:
        // (srv->clt)
        case PGSQL_ERROR_RESPONSE:
        case PGSQL_AUTHENTIFICATION:
            return STARTUP;
        // 0 is probably the first byte of the 32 bit length of init message
        case 0:
        default:
            return NONE;
    }
}

static enum proto_parse_status pg_sbuf_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct pgsql_parser *pg_parser = DOWNCAST(parser, parser, pgsql_parser);
    if (cap_len < 1) return PROTO_PARSE_ERR;

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
    // TODO handle first_ts on stream restart
    info.first_ts = *now;

    uint8_t type = payload[0];
    // Try to guess when phase is unknown
    if (pg_parser->phase == NONE) {
        pg_parser->phase = guess_phase(type);
        SLOG(LOG_DEBUG, "Phase %s detected", pgsql_phase_2_str(pg_parser->phase));
    }
    // Try to detect query
    bool is_query = info.is_query;
    is_query_type(type, &is_query);
    if (info.is_query != is_query) {
        SLOG(LOG_DEBUG, "Fix c2s_way to %u", way);
        pg_parser->c2s_way = way;
        info.is_query = !info.is_query;
    }

    SLOG(LOG_DEBUG, "Phase %s, query: %d, type: %s", pgsql_phase_2_str(pg_parser->phase), info.is_query,
            pgsql_msg_type_2_str(type, info.is_query));
    switch (pg_parser->phase) {
        case NONE:    return pg_parse_init_phase   (pg_parser, &info, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);
        case STARTUP: return pg_parse_startup_phase(pg_parser, &info, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);
        case QUERY:   return pg_parse_query_phase  (pg_parser, &info, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);
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
