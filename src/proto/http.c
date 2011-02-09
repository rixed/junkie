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
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <inttypes.h>
#include <junkie/tools/tempstr.h>
#include <junkie/tools/mallocer.h>
#include <junkie/proto/tcp.h>
#include <junkie/proto/http.h>
#include <junkie/proto/streambuf.h>
#include <junkie/cpp.h>
#include <junkie/tools/log.h>
#include "proto/httper.h"
#include "proto/liner.h"


static char const Id[] = "$Id: 0477d160214401d1ceeb489639cc1a86210de55d $";

#define HTTP_TIMEOUT (60 * 3)  // 3min should be enough for every web server

#undef LOG_CAT
#define LOG_CAT proto_http_log_category

LOG_CATEGORY_DEF(proto_http);

struct http_parser {
    struct parser parser;
    unsigned c2s_way;   // The way when traffic is going from client to server (~0U for unset)
    struct streambuf sbuf;
    struct http_state {
        enum http_phase {
            NONE,   // before initial header was met
            BODY,   // while scanning body
            LOST,   // when we have lost the message boundaries because of uncaptured bytes
        } phase;
#       define UNKNOWN_REM_CONTENT ((size_t)((ssize_t)-1))
        size_t remaining_content;   // nb bytes before next header (or (ssize_t)-1 if unknown). Only relevant when phase=BODY.
        // FIXME: take into account http-range?
    } state[2];    // One per direction (depending on "way", ie. 0 will be smaller IP)
};

static parse_fun http_sbuf_parse;

static int http_parser_ctor(struct http_parser *http_parser, struct proto *proto, struct timeval const *now)
{
    assert(proto == proto_http);
    if (0 != parser_ctor(&http_parser->parser, proto, now)) return -1;
    http_parser->state[0].phase = NONE;
    http_parser->state[1].phase = NONE;
    http_parser->c2s_way = ~0U;
#   define HTTP_MAX_HDR_SIZE 10000   // in bytes
    if (0 != streambuf_ctor(&http_parser->sbuf, http_sbuf_parse, HTTP_MAX_HDR_SIZE)) return -1;

    return 0;
}

static struct parser *http_parser_new(struct proto *proto, struct timeval const *now)
{
    MALLOCER(http_parsers);
    struct http_parser *http_parser = MALLOC(http_parsers, sizeof(*http_parser));
    if (! http_parser) return NULL;

    if (-1 == http_parser_ctor(http_parser, proto, now)) {
        FREE(http_parser);
        return NULL;
    }

    return &http_parser->parser;
}

static void http_parser_dtor(struct http_parser *http_parser)
{
    parser_dtor(&http_parser->parser);
    streambuf_dtor(&http_parser->sbuf);
}

static void http_parser_del(struct parser *parser)
{
    struct http_parser *http_parser = DOWNCAST(parser, parser, http_parser);
    http_parser_dtor(http_parser);
    FREE(http_parser);
}

/*
 * Misc
 */

char const *http_method_2_str(enum http_method method)
{
    switch (method) {
        case HTTP_METHOD_GET:     return "GET";
        case HTTP_METHOD_HEAD:    return "HEAD";
        case HTTP_METHOD_POST:    return "POST";
        case HTTP_METHOD_CONNECT: return "CONNECT";
        case HTTP_METHOD_PUT:     return "PUT";
        case HTTP_METHOD_OPTIONS: return "OPTIONS";
        case HTTP_METHOD_TRACE:   return "TRACE";
        case HTTP_METHOD_DELETE:  return "DELETE";
    }
    FAIL("Invalid HTTP method (%d)", method);
    return "INVALID";
}


/*
 * Proto Infos
 */

static void const *http_info_addr(struct proto_info const *info_, size_t *size)
{
    struct http_proto_info const *info = DOWNCAST(info_, info, http_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

char const *http_info_2_str(struct proto_info const *info_)
{
    struct http_proto_info const *info = DOWNCAST(info_, info, http_proto_info);
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "%s, method=%s, code=%s, content_length=%s, mime_type=%s, host=%s, url=%s",
        proto_info_2_str(info_),
        info->set_values & HTTP_METHOD_SET   ? http_method_2_str(info->method)             : "unset",
        info->set_values & HTTP_CODE_SET     ? tempstr_printf("%u", info->code)            : "unset",
        info->set_values & HTTP_LENGTH_SET   ? tempstr_printf("%zu", info->content_length) : "unset",
        info->set_values & HTTP_MIME_SET     ? info->mime_type                             : "unset",
        info->set_values & HTTP_HOST_SET     ? info->host                                  : "unset",
        info->set_values & HTTP_URL_SET      ? info->url                                   : "unset");
    return str;
}

static void http_proto_info_ctor(struct http_proto_info *info, struct http_parser *http_parser, struct proto_info *parent, size_t head_len, size_t payload)
{
    proto_info_ctor(&info->info, &http_parser->parser, parent, head_len, payload);
}

/*
 * Parse HTTP header
 */

static int http_set_method(unsigned cmd, struct liner *liner, void *info_)
{
    struct http_proto_info *info = info_;
    info->set_values |= HTTP_METHOD_SET;
    info->method = cmd;
    // URL is the next token
    if (! liner_eof(liner)) {
        info->set_values |= HTTP_URL_SET;
        copy_token(info->url, sizeof(info->url), liner);
    }
    return 0;
}

static int http_extract_code(unsigned unused_ cmd, struct liner *liner, void *info_)
{
    struct http_proto_info *info = info_;
    info->code = liner_strtoull(liner, NULL, 10);
    info->set_values |= HTTP_CODE_SET;
    return 0;
}

static int http_extract_content_length(unsigned unused_ field, struct liner *liner, void *info_)
{
    struct http_proto_info *info = info_;
    info->set_values |= HTTP_LENGTH_SET;
    info->content_length = liner_strtoull(liner, NULL, 10);
    return 0;
}

static int http_extract_content_type(unsigned unused_ field, struct liner *liner, void *info_)
{
    struct http_proto_info *info = info_;
    info->set_values |= HTTP_MIME_SET;
    copy_token(info->mime_type, sizeof(info->mime_type), liner);
    return 0;
}

static int http_extract_transfert_encoding(unsigned unused_ field, struct liner unused_ *liner, void *info_)
{
    // Actually we don't care about the exact transfert encoding, bu we need to know whether it's set or not
    struct http_proto_info *info = info_;
    info->set_values |= HTTP_TRANSFERT_ENCODING_SET;
    return 0;
}

static int http_extract_host(unsigned unused_ field, struct liner *liner, void *info_)
{
    struct http_proto_info *info = info_;
    info->set_values |= HTTP_HOST_SET;
    copy_token(info->host, sizeof(info->host), liner);
    return 0;
}

static enum proto_parse_status http_parse_header(struct http_parser *http_parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn, size_t tot_cap_len, uint8_t const *tot_packet)
{
    // Sanity checks + Parse
    static struct httper_command const commands[] = {
        [HTTP_METHOD_GET]      = { "GET",      3, http_set_method },
        [HTTP_METHOD_HEAD]     = { "HEAD",     4, http_set_method },
        [HTTP_METHOD_POST]     = { "POST",     4, http_set_method },
        [HTTP_METHOD_CONNECT]  = { "CONNECT",  7, http_set_method },
        [HTTP_METHOD_PUT]      = { "PUT",      3, http_set_method },
        [HTTP_METHOD_OPTIONS]  = { "OPTIONS",  7, http_set_method },
        [HTTP_METHOD_TRACE]    = { "TRACE",    5, http_set_method },
        [HTTP_METHOD_DELETE]   = { "DELETE",   6, http_set_method },
        [HTTP_METHOD_DELETE+1] = { "HTTP/1.1", 8, http_extract_code },
        [HTTP_METHOD_DELETE+2] = { "HTTP/1.0", 8, http_extract_code },
    };
    static struct httper_field const fields[] = {
        { "content-length",    14, http_extract_content_length },
        { "content-type",      12, http_extract_content_type },
        { "transfer-encoding", 17, http_extract_transfert_encoding },
        { "host",               4, http_extract_host },
    };
    static struct httper const httper = {
        .nb_commands = NB_ELEMS(commands),
        .commands = commands,
        .nb_fields = NB_ELEMS(fields),
        .fields = fields
    };

    struct http_proto_info info;    // we init the proto_info once validated
    info.set_values = 0;

    size_t httphdr_len;
    enum proto_parse_status status = httper_parse(&httper, &httphdr_len, packet, cap_len, &info);
    if (status == PROTO_PARSE_ERR) return PROTO_PARSE_ERR;
    if (status == PROTO_TOO_SHORT) {
        // Are we going to receive the end eventually?
        if (wire_len == cap_len) {
            status = proto_parse(NULL, parent, way, NULL, 0, 0, now, okfn, tot_cap_len, tot_packet);    // ack what we had so far
            streambuf_set_restart(&http_parser->sbuf, way, packet, true);
            return PROTO_OK;
        } else {    // No, the header was truncated. We want to report as much as we can
            // Notice that we have no idea of the actual size of header and payload, by we want to report all bytes,
            // ie that out header+payload = wire_len.
            http_proto_info_ctor(&info, http_parser, parent, cap_len, wire_len - cap_len);
            return proto_parse(NULL, &info.info, way, NULL, 0, 0, now, okfn, tot_cap_len, tot_packet);
            // We are going to look for another header in the next packet, hoping for the best.
        }
    }

    /* Now we have several possible cases :
     * - all the remaining of this packet belongs to the payload of this header, so the packet is fully
     *   parsed and we are done
     * - the next header is in this very packet, so we must restart to parse in NONE phase after having
     *   reported this header, at once (ie. before reception of new data).
     */
    assert(httphdr_len <= cap_len);
    size_t const rem_bytes = wire_len - httphdr_len;

    if ((info.set_values & HTTP_LENGTH_SET) && info.content_length < rem_bytes) {
        // Next header to come in same packet
        http_proto_info_ctor(&info, http_parser, parent, httphdr_len, info.content_length);
        // but do we have it in the captured bytes ?
        if (info.content_length >= cap_len) {
            // we can report this message but we can't report next one.
            http_parser->state[way].phase = LOST;
        } else {
            streambuf_set_restart(&http_parser->sbuf, way, packet + info.content_length, false);
        }
    } else {
        // Next header, if any, will come later
        http_proto_info_ctor(&info, http_parser, parent, httphdr_len, rem_bytes);
        bool const have_body = info.set_values & (HTTP_LENGTH_SET | HTTP_TRANSFERT_ENCODING_SET);
        http_parser->state[way].phase = have_body ? BODY : NONE;
        http_parser->state[way].remaining_content = info.set_values & HTTP_LENGTH_SET ? info.content_length - rem_bytes : UNKNOWN_REM_CONTENT;
    }

    return proto_parse(NULL, &info.info, way, NULL, 0, 0, now, okfn, tot_cap_len, tot_packet);
}

/*
 * Parse HTTP Body
 */

static enum proto_parse_status http_parse_body(struct http_parser *http_parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn, size_t tot_cap_len, uint8_t const *tot_packet)
{
    // In this phase, either we known the content length and we skip it before returning to NONE phase,
    // or we don't know and we just skip everything.
    SLOG(LOG_DEBUG, "Parsing body, remaining %zu bytes", http_parser->state[way].remaining_content);

    size_t const body_part =    // The part of wire_len that belongs to the current body
        http_parser->state[way].remaining_content == UNKNOWN_REM_CONTENT || http_parser->state[way].remaining_content > wire_len ?
            wire_len :
            http_parser->state[way].remaining_content;
    SLOG(LOG_DEBUG, "%zu bytes of this payload belongs to the body", body_part);

    if (body_part > 0) {    // Ack this body part
        struct http_proto_info info;
        info.set_values = 0;
        http_proto_info_ctor(&info, http_parser, parent, 0, body_part);
        // TODO: choose a subparser according to mime type ?
        (void)proto_parse(NULL, &info.info, way, NULL, 0, 0, now, okfn, tot_cap_len, tot_packet);
        // What to do with this partial parse status ?
    }

    if (http_parser->state[way].remaining_content != UNKNOWN_REM_CONTENT) {
        assert(http_parser->state[way].remaining_content >= body_part);
        http_parser->state[way].remaining_content -= body_part;
    }

    if (http_parser->state[way].remaining_content == 0) {
        http_parser->state[way].phase = NONE;
        if (body_part == wire_len) return PROTO_OK;
        if (body_part >= cap_len) {
            // Next header was not captured :-(
            return PROTO_TOO_SHORT;
        }
        // Else the header is already waiting for us
        streambuf_set_restart(&http_parser->sbuf, way, packet + body_part, false);
    }

    return PROTO_OK;
}

/*
 * Proto API
 */

static enum proto_parse_status http_sbuf_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct http_parser *http_parser = DOWNCAST(parser, parser, http_parser);

    // If this is the first time we are called, init c2s_way
    if (http_parser->c2s_way == ~0U) {
        http_parser->c2s_way = way;
        SLOG(LOG_DEBUG, "First packet, init c2s_way to %u", http_parser->c2s_way);
    }

    // Now are we waiting the header, or scanning through body ?
    SLOG(LOG_DEBUG, "Http parser@%p is %s", http_parser, http_parser->state[way].phase == NONE ? "waiting header" : "waiting end of body");
    switch (http_parser->state[way].phase) {
        case NONE:  // In this mode we retry until we manage to parse a header
           return http_parse_header(http_parser, parent, way, payload, cap_len, wire_len, now, okfn, tot_cap_len, tot_packet);
        case BODY:
           return http_parse_body(http_parser, parent, way, payload, cap_len, wire_len, now, okfn, tot_cap_len, tot_packet);
        case LOST:
           return PROTO_TOO_SHORT;
    }

    assert(!"Invalid http parser phase");
    return -1;
}

static enum proto_parse_status http_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct http_parser *http_parser = DOWNCAST(parser, parser, http_parser);

    return streambuf_add(&http_parser->sbuf, parser, parent, way, payload, cap_len, wire_len, now, okfn, tot_cap_len, tot_packet);
}

/*
 * Init
 */

static struct proto proto_http_;
struct proto *proto_http = &proto_http_;
static struct port_muxer tcp_port_muxer;

void http_init(void)
{
    log_category_proto_http_init();

    static struct proto_ops const ops = {
        .parse      = http_parse,
        .parser_new = http_parser_new,
        .parser_del = http_parser_del,
        .info_2_str = http_info_2_str,
        .info_addr  = http_info_addr,
    };
    proto_ctor(&proto_http_, &ops, "HTTP", HTTP_TIMEOUT);
    port_muxer_ctor(&tcp_port_muxer, &tcp_port_muxers, 80, 80, proto_http);
}

void http_fini(void)
{
    port_muxer_dtor(&tcp_port_muxer, &tcp_port_muxers);
    proto_dtor(&proto_http_);
    log_category_proto_http_fini();
}

/*
 * Utilities
 */

#define HTTP_SEL "http://"
#define HTTP_SEL_LEN 7

static bool end_of_host(int c)
{
    return c == '\0' || c == '/' || c == ':';
}

char const *http_build_domain(struct ip_addr const *server, char const *host, char const *url, int version)
{
    char const *src = NULL;
    if (host) {
        src = host;
    } else if (url && 0 == strncasecmp(url, HTTP_SEL, HTTP_SEL_LEN)) {
        src = url + HTTP_SEL_LEN;
    }

    if (! src) return (version == 6 ? ip_addr_2_strv6:ip_addr_2_str)(server);

    // takes everything from url+HTTP_SEL_LEN up to '\0', ':' or '/'
    char *str = tempstr();
    unsigned c;
    for (c = 0; c < TEMPSTR_SIZE-1 && !end_of_host(src[c]); c++) {
        str[c] = src[c];
    }
    str[c] = '\0';
    return str;
}

char const *http_build_url(struct ip_addr const *server, char const *host, char const *url)
{
    if (url && 0 == strncasecmp(url, HTTP_SEL, HTTP_SEL_LEN)) {
        url += HTTP_SEL_LEN;
        // Remove port from url
        char const *colon = url;
        while (! end_of_host(*colon)) colon ++;
        if (*colon != ':') return url;
        char *str = tempstr();
        char const *end_port = colon;
        while (! end_of_host(*end_port)) end_port ++;
        if (*end_port == ':') return url; // ?
        snprintf(str, TEMPSTR_SIZE, "%.*s%s", (int)(colon-url), url, end_port != '\0' ? end_port+1:end_port);
        return str;
    } else {    // url does not include host
        char *str = tempstr();
        snprintf(str, TEMPSTR_SIZE, "%s%s%s",
            http_build_domain(server, host, url, 4),
            !url || url[0] == '/' ? "" : "/",
            url ? url : "");
        return str;
    }
}

