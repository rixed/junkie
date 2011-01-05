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
#include <junkie/cpp.h>
#include <junkie/tools/log.h>
#include <junkie/tools/tempstr.h>
#include <junkie/tools/mallocer.h>
#include <junkie/proto/proto.h>
#include <junkie/proto/tcp.h>
#include <junkie/proto/postgres.h>
#include <junkie/proto/streambuf.h>

static char const Id[] = "$Id$";

#define PG_TIMEOUT (60 * 15)  // 15min should be enough for every request

#undef LOG_CAT
#define LOG_CAT proto_postgres_log_category

LOG_CATEGORY_DEF(proto_postgres);

struct postgres_parser {
    struct parser parser;
    unsigned c2s_way;       // The way when traffic is going from client to server (~0U for unset)
    enum phase { NONE, STARTUP, QUERY, EXIT } phase;
    struct streambuf sbuf;
};

static parse_fun pg_sbuf_parse;

static int pg_parser_ctor(struct postgres_parser *pg_parser, struct proto *proto, struct timeval const *now)
{
    assert(proto == proto_postgres);
    if (0 != parser_ctor(&pg_parser->parser, proto, now)) return -1;
    pg_parser->phase = NONE;
    pg_parser->c2s_way = ~0U;    // unset
    if (0 != streambuf_ctor(&pg_parser->sbuf, pg_sbuf_parse, 30000)) return -1;

    return 0;
}

static struct parser *pg_parser_new(struct proto *proto, struct timeval const *now)
{
    MALLOCER(pg_parsers);
    struct postgres_parser *pg_parser = MALLOC(pg_parsers, sizeof(*pg_parser));
    if (! pg_parser) return NULL;

    if (-1 == pg_parser_ctor(pg_parser, proto, now)) {
        FREE(pg_parser);
        return NULL;
    }

    return &pg_parser->parser;
}

static void pg_parser_dtor(struct postgres_parser *pg_parser)
{
    parser_dtor(&pg_parser->parser);
    streambuf_dtor(&pg_parser->sbuf);
}

static void pg_parser_del(struct parser *parser)
{
    struct postgres_parser *pg_parser = DOWNCAST(parser, parser, postgres_parser);
    pg_parser_dtor(pg_parser);
    FREE(pg_parser);
}

/*
 * Proto infos
 */

static char const *pg_ssl_2_str(enum pg_ssl ssl)
{
    switch (ssl) {
        case PG_SSL_REQUESTED: return "SSL requested";
        case PG_SSL_GRANTED:   return "SSL granted";
        case PG_SSL_REFUSED:   return "SSL refused";
    }
    assert(!"Unknown pg_ssl");
    return "INVALID";
}

static char const *pg_msg_type_2_str(enum pg_msg_type type)
{
    switch (type) {
        case PG_STARTUP: return "startup";
        case PG_QUERY:   return "query";
        case PG_EXIT:    return "exit";
    }
    assert(!"Unknown pg_msg_type");
    return "INVALID";
}

static char const *startup_query_2_str(struct postgres_proto_info const *info)
{
    return tempstr_printf(", %s%s%s%s%s%s%s",
        info->set_values & PG_SSL_REQUEST ? pg_ssl_2_str(info->u.startup.ssl_request) : "No SSL",
        info->set_values & PG_USER   ? ", user=" : "",
        info->set_values & PG_USER   ? info->u.startup.user : "",
        info->set_values & PG_DBNAME ? ", dbname=" : "",
        info->set_values & PG_DBNAME ? info->u.startup.dbname : "",
        info->set_values & PG_PASSWD ? ", passwd=" : "",
        info->set_values & PG_PASSWD ? info->u.startup.passwd : "");
}

static char const *startup_reply_2_str(struct postgres_proto_info const *info)
{
    return tempstr_printf(", %s%s",
        info->set_values & PG_SSL_REQUEST ? pg_ssl_2_str(info->u.startup.ssl_request) : "No SSL",
        info->set_values & PG_CNX_DONE    ? ", Authentication OK":"");
}

static char const *query_query_2_str(struct postgres_proto_info const *info)
{
    return tempstr_printf("%s%s%s",
        info->set_values & PG_SQL ? ", query='" : "",
        info->set_values & PG_SQL ? info->u.query.sql : "",
        info->set_values & PG_SQL ? "'" : "");
}

static char const *query_reply_2_str(struct postgres_proto_info const *info)
{
    return tempstr_printf(", status=%d, nb_rows=%d, nb_fields=%d",
        info->set_values & PG_STATUS    ? (int)info->u.query.status : -1,
        info->set_values & PG_NB_ROWS   ? (int)info->u.query.nb_rows : -1,
        info->set_values & PG_NB_FIELDS ? (int)info->u.query.nb_fields : -1);
}

static char const *exit_2_str(struct postgres_proto_info const unused_ *info)
{
    return "";
}

static char const *pg_info_2_str(struct proto_info const *info_)
{
    struct postgres_proto_info const *info = DOWNCAST(info_, info, postgres_proto_info);
    char *str = tempstr();

    char const *(*spec_info_2_str)(struct postgres_proto_info const *);
    switch (info->msg_type) {
        case PG_STARTUP:
            spec_info_2_str = info->is_query ? startup_query_2_str : startup_reply_2_str;
            break;
        case PG_QUERY:
            spec_info_2_str = info->is_query ? query_query_2_str : query_reply_2_str;
            break;
        case PG_EXIT:
            spec_info_2_str = exit_2_str;
            break;
    }

    snprintf(str, TEMPSTR_SIZE, "%s, %s%s",
        proto_info_2_str(info_),
        pg_msg_type_2_str(info->msg_type),
        spec_info_2_str(info));

    return str;
}

static void const *pg_info_addr(struct proto_info const *info_, size_t *size)
{
    struct postgres_proto_info const *info = DOWNCAST(info_, info, postgres_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

/*
 * Parse
 */

struct cursor {
    uint8_t const *head;
    size_t cap_len;     // remaining length that can be read
};

static void cursor_rollback(struct cursor *cursor, unsigned n)
{
    cursor->cap_len += n;
    cursor->head -= n;
}

#define CHECK_LEN(cursor, x, rollback) do { \
    if ((cursor)->cap_len  < (x)) { cursor_rollback(cursor, rollback); return PROTO_TOO_SHORT; } \
} while(0)

static void cursor_ctor(struct cursor *cursor, uint8_t const *head, size_t cap_len)
{
    cursor->head = head;
    cursor->cap_len = cap_len;
}

static uint8_t cursor_read_u8(struct cursor *cursor)
{
    assert(cursor->cap_len >= 1);
    cursor->cap_len --;
    SLOG(LOG_DEBUG, "Reading byte 0x%x, %zu left", *cursor->head, cursor->cap_len);
    return *cursor->head++;
}

static uint16_t cursor_read_u16n(struct cursor *cursor)
{
    uint32_t a = cursor_read_u8(cursor);
    uint32_t b = cursor_read_u8(cursor);
    return (a << 8) | b;
}

static uint32_t cursor_read_u32n(struct cursor *cursor)
{
    uint32_t a = cursor_read_u8(cursor);
    uint32_t b = cursor_read_u8(cursor);
    uint32_t c = cursor_read_u8(cursor);
    uint32_t d = cursor_read_u8(cursor);
    return (a << 24) | (b << 16) | (c << 8) | d;
}

// returns a tempstr with the (beginning of the) string
// max_len is the maximum number of bytes to read. If it's reached before the end of string (nul) then
// PROTO_TOO_SHORT is returned (and the cursor is rollbacked)
static enum proto_parse_status cursor_read_string(struct cursor *cursor, char **str_, size_t max_len)
{
    char *str = tempstr();
    unsigned len;
    if (max_len > TEMPSTR_SIZE-1) max_len = TEMPSTR_SIZE-1;

    for (len = 0; len < max_len; len ++) {
        CHECK_LEN(cursor, 1, len);
        uint8_t c = cursor_read_u8(cursor);
        if (c == '\0') break;
        str[len] = c;
    }
    if (len == max_len) {
        cursor_rollback(cursor, len);
        return PROTO_TOO_SHORT;
    }

    str[len] = '\0';

    SLOG(LOG_DEBUG, "Reading string '%s'", str);

    if (str_) *str_ = str;
    return PROTO_OK;
}

static void cursor_drop(struct cursor *cursor, unsigned n)
{
    assert(cursor->cap_len >= n);
    cursor->cap_len -= n;
    cursor->head += n;
}

static bool cursor_is_empty(struct cursor const *cursor)
{
    return cursor->cap_len == 0;
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

static enum proto_parse_status pg_parse_init(struct postgres_parser *pg_parser, struct postgres_proto_info *info, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn)
{
    info->msg_type = PG_STARTUP;

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
            info->set_values |= PG_SSL_REQUEST;
            info->u.startup.ssl_request = PG_SSL_REQUESTED;
        } else if (msg == 196608) { // version number, here 00 03 00 00 (ie. 3.0), which is parsed here
            SLOG(LOG_DEBUG, "Msg is a startup message for v3.0");
            // fine, now parse all the strings that follow
            do {
                char *name, *value;
                status = cursor_read_string(&cursor, &name, len);
                if (status != PROTO_OK) return status;
                if (name[0] == '\0') break;
                status = cursor_read_string(&cursor, &value, len);
                if (status != PROTO_OK) return status;
                if (0 == strcmp(name, "user")) {
                    info->set_values |= PG_USER;
                    snprintf(info->u.startup.user, sizeof(info->u.startup.user), "%s", value);
                } else if (0 == strcmp(name, "database")) {
                    info->set_values |= PG_DBNAME;
                    snprintf(info->u.startup.dbname, sizeof(info->u.startup.dbname), "%s", value);
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
        info->set_values |= PG_SSL_REQUEST;
        if (payload[0] == 'S') {
            info->u.startup.ssl_request = PG_SSL_GRANTED;  // We will get parse errors from now on :-<
        } else if (payload[0] == 'N') {
            info->u.startup.ssl_request = PG_SSL_REFUSED;
        } else {
            return PROTO_PARSE_ERR;
        }
    }

    return proto_parse(NULL, &info->info, way, NULL, 0, 0, now, okfn);
}

static enum proto_parse_status pg_parse_startup(struct postgres_parser *pg_parser, struct postgres_proto_info *info, unsigned way, uint8_t const *payload, size_t cap_len, size_t unused_ wire_len, struct timeval const *now, proto_okfn_t *okfn)
{
    info->msg_type = PG_STARTUP;

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
        info->set_values |= PG_PASSWD;
        snprintf(info->u.startup.passwd, sizeof(info->u.startup.passwd), "%s", passwd);
    } else {    // Authentication request
        if (type != 'R' || len < 4) return PROTO_PARSE_ERR;
        // We don't care about the auth method, we just want to know when auth is complete
        uint32_t auth_type = cursor_read_u32n(&cursor);
        if (auth_type == 0) {   // AuthenticationOK
            pg_parser->phase = QUERY;   // we don't wait for the ReadyForQuery msg since we are not interrested in following messages
            info->set_values |= PG_CNX_DONE;
        }
    }

    // Discard the rest of the packet
    return proto_parse(NULL, &info->info, way, NULL, 0, 0, now, okfn);
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

static enum proto_parse_status pg_parse_query(struct postgres_parser *pg_parser, struct postgres_proto_info *info, unsigned way, uint8_t const *payload, size_t cap_len, size_t unused_ wire_len, struct timeval const *now, proto_okfn_t *okfn)
{
    enum proto_parse_status status;
    info->msg_type = PG_QUERY;

    struct cursor cursor;
    cursor_ctor(&cursor, payload, cap_len);
    uint8_t type;
    size_t len;

    /* In this phase, we are looking for SimpleQuery from the client and Data from the server.
     * This is very simplistic, to be completed later with more interresting query types.
     * Also, the client can send a termination request. */
    if (info->is_query) {
        status = cursor_read_msg(&cursor, &type, &len);
        if (status != PROTO_OK) return status;

        if (type == 'Q') {  // simple query
            char *sql;
            status = cursor_read_string(&cursor, &sql, len);
            if (status != PROTO_OK) return status;
            info->set_values |= PG_SQL;
            snprintf(info->u.query.sql, sizeof(info->u.query.sql), "%s", sql);
        } else if (type == 'X') {
            info->msg_type = PG_EXIT;
            pg_parser->phase = EXIT;
        } else return PROTO_PARSE_ERR;
    } else {
        while (! cursor_is_empty(&cursor)) {
            uint8_t const *const msg_start = cursor.head;
            status = cursor_read_msg(&cursor, &type, &len);
            if (status == PROTO_PARSE_ERR) return status;
            else if (status == PROTO_TOO_SHORT) {
                SLOG(LOG_DEBUG, "Payload too short for parsing message, will restart");
                status = proto_parse(NULL, &info->info, way, NULL, 0, 0, now, okfn);    // ack what we had so far
                streambuf_set_restart(&pg_parser->sbuf, way, msg_start);
                return PROTO_OK;
            }

            uint8_t const *const msg_end = cursor.head + len;
            if (type == 'T') {  // row description (fetch nb_fields)
                if (len < 2) return PROTO_PARSE_ERR;
                info->u.query.nb_fields = cursor_read_u16n(&cursor);
                info->set_values |= PG_NB_FIELDS;
                SLOG(LOG_DEBUG, "Setting nb_fields to %u", info->u.query.nb_fields);
            } else if (type == 'D') {   // data row
                if (len < 2) return PROTO_PARSE_ERR;
                if (! (info->set_values & PG_NB_ROWS)) {
                    info->set_values |= PG_NB_ROWS;
                    info->u.query.nb_rows = 0;
                }
                info->u.query.nb_rows ++;
                SLOG(LOG_DEBUG, "Incrementing nb_rows (now %u)", info->u.query.nb_rows);
            } else if (type == 'C') {   // command complete (fetch nb rows)
                char *result;
                status = cursor_read_string(&cursor, &result, len);
                if (status != PROTO_OK) return status;
                status = fetch_nb_rows(result, &info->u.query.nb_rows);
                if (status == PROTO_OK) {
                    info->set_values |= PG_NB_ROWS;
                } else {
                    //return status;    // Do not use this as the actual protocol does not seam to implement the doc :-<
                }
            } else if (type == 'E') {   // error
                SLOG(LOG_DEBUG, "Ask for termination");
                info->set_values |= PG_STATUS;
                info->u.query.status = -1;  // TODO: fetch an error code
            }
            // Skip what's left of this message and go for the next
            assert(msg_end >= cursor.head);
            cursor_drop(&cursor, msg_end - cursor.head);
        }
    }

    return proto_parse(NULL, &info->info, way, NULL, 0, 0, now, okfn);
}

static enum proto_parse_status pg_sbuf_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn)
{
    struct postgres_parser *pg_parser = DOWNCAST(parser, parser, postgres_parser);

    // If this is the first time we are called, init c2s_way
    if (pg_parser->c2s_way == ~0U) {
        SLOG(LOG_DEBUG, "First packet, init c2s_way to %u", way);
        pg_parser->c2s_way = way;
    }

    // Now build the proto_info
    struct postgres_proto_info info;
    proto_info_ctor(&info.info, parser, parent, wire_len, 0);
    info.is_query = way == pg_parser->c2s_way;
    info.set_values = 0;

    switch (pg_parser->phase) {
        case NONE:    return pg_parse_init   (pg_parser, &info, way, payload, cap_len, wire_len, now, okfn);
        case STARTUP: return pg_parse_startup(pg_parser, &info, way, payload, cap_len, wire_len, now, okfn);
        case QUERY:   return pg_parse_query  (pg_parser, &info, way, payload, cap_len, wire_len, now, okfn);
        case EXIT:    return PROTO_PARSE_ERR;   // we do not expect payload after a termination message
    }

    return PROTO_PARSE_ERR;
}

static enum proto_parse_status pg_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn)
{
    struct postgres_parser *pg_parser = DOWNCAST(parser, parser, postgres_parser);

    return streambuf_add(&pg_parser->sbuf, parser, parent, way, payload, cap_len, wire_len, now, okfn);
}

/*
 * Construction/Destruction
 */

static struct proto proto_postgres_;
struct proto *proto_postgres = &proto_postgres_;
static struct port_muxer pg_tcp_muxer;

void postgres_init(void)
{
    log_category_proto_postgres_init();

    static struct proto_ops const ops = {
        .parse      = pg_parse,
        .parser_new = pg_parser_new,
        .parser_del = pg_parser_del,
        .info_2_str = pg_info_2_str,
        .info_addr  = pg_info_addr,
    };
    proto_ctor(&proto_postgres_, &ops, "PostgreSQL", PG_TIMEOUT);
    port_muxer_ctor(&pg_tcp_muxer, &tcp_port_muxers, 5432, 5432, proto_postgres);
}

void postgres_fini(void)
{
    port_muxer_dtor(&pg_tcp_muxer, &tcp_port_muxers);
    proto_dtor(&proto_postgres_);
    log_category_proto_postgres_fini();
}
