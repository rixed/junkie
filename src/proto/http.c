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
#include "junkie/tools/tempstr.h"
#include "junkie/tools/objalloc.h"
#include "junkie/tools/mutex.h"
#include "junkie/proto/serialize.h"
#include "junkie/proto/tcp.h"
#include "junkie/proto/http.h"
#include "junkie/proto/streambuf.h"
#include "junkie/cpp.h"
#include "junkie/tools/log.h"
#include "proto/httper.h"
#include "proto/liner.h"


#undef LOG_CAT
#define LOG_CAT proto_http_log_category

LOG_CATEGORY_DEF(proto_http);

struct http_parser {
    struct parser parser;
    struct mutex mutex;     // Essentially to protect the streambuf
    unsigned c2s_way;   // The way when traffic is going from client to server (~0U for unset)
    struct streambuf sbuf;
    struct http_state {
        enum http_phase {
            HEAD,       // while waiting for/scanning header
            BODY,       // while scanning body
            CHUNK_HEAD, // while scanning a chunk header
            CHUNK,      // while scanning a body chunk
        } phase;
#       define CONTENT_UP_TO_END ((size_t)((ssize_t)-1))
        size_t remaining_content;   // nb bytes before next header (or (ssize_t)-1 if unknown). Only relevant when phase=BODY|CHUNK.
        // Store the last query command, to be taken it into account to skip body in answer to HEADs
        enum http_method last_method;
        // FIXME: parse transfert-encoding: chunked
        // FIXME: take into account http-range?
    } state[2];    // One per direction (depending on "way", ie. 0 will be smaller IP)
};

static char const *http_parser_phase_2_str(enum http_phase phase)
{
    switch (phase) {
        case HEAD: return "waiting/scanning headers";
        case BODY: return "scanning body";
        case CHUNK: return "scanning chunk content";
        case CHUNK_HEAD: return "scanning chunk header";
    }
    assert(!"Unknown HTTP pase");
}

static parse_fun http_sbuf_parse;

static int http_parser_ctor(struct http_parser *http_parser, struct proto *proto)
{
    SLOG(LOG_DEBUG, "Construct HTTP parser@%p", http_parser);

    assert(proto == proto_http);
    if (0 != parser_ctor(&http_parser->parser, proto)) return -1;
    http_parser->state[0].phase = HEAD;
    http_parser->state[1].phase = HEAD;
    http_parser->state[0].last_method = ~0U;
    http_parser->state[1].last_method = ~0U;
    http_parser->c2s_way = ~0U;
#   define HTTP_MAX_HDR_SIZE 10000   // in bytes
    if (0 != streambuf_ctor(&http_parser->sbuf, http_sbuf_parse, HTTP_MAX_HDR_SIZE)) return -1;
    mutex_ctor(&http_parser->mutex, "http");

    return 0;
}

static struct parser *http_parser_new(struct proto *proto)
{
    struct http_parser *http_parser = objalloc(sizeof(*http_parser), "HTTP parsers");
    if (! http_parser) return NULL;

    if (-1 == http_parser_ctor(http_parser, proto)) {
        objfree(http_parser);
        return NULL;
    }

    return &http_parser->parser;
}

static void http_parser_dtor(struct http_parser *http_parser)
{
    SLOG(LOG_DEBUG, "Destruct HTTP parser@%p", http_parser);

    parser_dtor(&http_parser->parser);
    streambuf_dtor(&http_parser->sbuf);
    mutex_dtor(&http_parser->mutex);
}

static void http_parser_del(struct parser *parser)
{
    struct http_parser *http_parser = DOWNCAST(parser, parser, http_parser);
    http_parser_dtor(http_parser);
    objfree(http_parser);
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

static char const *http_info_2_str(struct proto_info const *info_)
{
    struct http_proto_info const *info = DOWNCAST(info_, info, http_proto_info);
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "%s, method=%s, code=%s, content_length=%s, transfert_encoding=%s, mime_type=%s, host=%s, url=%s",
        proto_info_2_str(info_),
        info->set_values & HTTP_METHOD_SET   ? http_method_2_str(info->method)            : "unset",
        info->set_values & HTTP_CODE_SET     ? tempstr_printf("%u", info->code)           : "unset",
        info->set_values & HTTP_LENGTH_SET   ? tempstr_printf("%u", info->content_length) : "unset",
        info->set_values & HTTP_TRANSFERT_ENCODING_SET ?
                                               (info->chunked_encoding ? "chunked":"set") : "unset",
        info->set_values & HTTP_MIME_SET     ? info->mime_type                            : "unset",
        info->set_values & HTTP_HOST_SET     ? info->host                                 : "unset",
        info->set_values & HTTP_URL_SET      ? info->url                                  : "unset");
    return str;
}

static void http_serialize(struct proto_info const *info_, uint8_t **buf)
{
    struct http_proto_info const *info = DOWNCAST(info_, info, http_proto_info);
    proto_info_serialize(info_, buf);
    serialize_1(buf, info->set_values);
    if (info->set_values & HTTP_METHOD_SET) serialize_1(buf, info->method);
    if (info->set_values & HTTP_CODE_SET) serialize_2(buf, info->code);
    if (info->set_values & HTTP_LENGTH_SET) serialize_4(buf, info->content_length);
    if (info->set_values & HTTP_TRANSFERT_ENCODING_SET) serialize_1(buf, info->chunked_encoding);
    if (info->set_values & HTTP_MIME_SET) serialize_str(buf, info->mime_type);
    if (info->set_values & HTTP_HOST_SET) serialize_str(buf, info->host);
    if (info->set_values & HTTP_URL_SET) serialize_str(buf, info->url);
}

static void http_deserialize(struct proto_info *info_, uint8_t const **buf)
{
    struct http_proto_info *info = DOWNCAST(info_, info, http_proto_info);
    proto_info_deserialize(info_, buf);
    info->set_values = deserialize_1(buf);
    if (info->set_values & HTTP_METHOD_SET) info->method = deserialize_1(buf);
    if (info->set_values & HTTP_CODE_SET) info->code = deserialize_2(buf);
    if (info->set_values & HTTP_LENGTH_SET) info->content_length = deserialize_4(buf);
    if (info->set_values & HTTP_TRANSFERT_ENCODING_SET) info->chunked_encoding = deserialize_1(buf);
    if (info->set_values & HTTP_MIME_SET) deserialize_str(buf, info->mime_type, sizeof(info->mime_type));
    if (info->set_values & HTTP_HOST_SET) deserialize_str(buf, info->host, sizeof(info->host));
    if (info->set_values & HTTP_URL_SET) deserialize_str(buf, info->url, sizeof(info->url));
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
    struct http_proto_info *info = info_;
    info->set_values |= HTTP_TRANSFERT_ENCODING_SET;
    info->chunked_encoding = 0 == strncasecmp(liner->start, "chunked", 7);
    return 0;
}

static int http_extract_host(unsigned unused_ field, struct liner *liner, void *info_)
{
    struct http_proto_info *info = info_;
    info->set_values |= HTTP_HOST_SET;
    copy_token(info->host, sizeof(info->host), liner);
    return 0;
}

static enum proto_parse_status http_parse_header(struct http_parser *http_parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    assert(http_parser->state[way].phase == HEAD);

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

    // Save some values into our http_parser
    http_parser->state[way].last_method =
        info.set_values & HTTP_METHOD_SET ? info.method : ~0U;

    // Handle short capture
    if (status == PROTO_TOO_SHORT) {
        // Are we going to receive the end eventually?
        if (wire_len == cap_len) {
            // So header end must be in next packet(s)
            status = proto_parse(NULL, parent, way, NULL, 0, 0, now, tot_cap_len, tot_packet);    // ack what we had so far
            streambuf_set_restart(&http_parser->sbuf, way, packet, true);   // retry later with (hopefully) complete header this time
            return PROTO_OK;
        } else {
            // No, the header was truncated. We want to report as much as we can.
            http_proto_info_ctor(&info, http_parser, parent, cap_len, 0);
            return proto_parse(NULL, &info.info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
            // We are going to look for another header at the start of the next packet, hoping for the best.
        }
    }

    /* What payload should we set? the one advertised? Or the payload of this header (ie 0),
     * and then let the body parser report other proto_info with head_len=0 and payload set?
     * will be definitively FIXED once we ditch this reporting policy for a hook based approach. */
    http_proto_info_ctor(&info, http_parser, parent, httphdr_len, 0);

    /* "The presence of a message-body in a request is signaled by the
     * inclusion of a Content-Length or Transfer-Encoding header field in
     * the request's message-headers."
     * "For response messages, whether or not a message-body is included with
     * a message is dependent on both the request method and the response
     * status code (section 6.1.1). All responses to the HEAD request method
     * MUST NOT include a message-body, even though the presence of entity-
     * header fields might lead one to believe they do. All 1xx
     * (informational), 204 (no content), and 304 (not modified) responses
     * MUST NOT include a message-body. All other responses do include a
     * message-body, although it MAY be of zero length." - RFC2616 */
    bool const have_body =
        (
            (info.set_values & HTTP_METHOD_SET) &&
            (info.set_values & (HTTP_LENGTH_SET | HTTP_TRANSFERT_ENCODING_SET))
        ) || (
            (info.set_values & HTTP_CODE_SET) &&
            http_parser->state[!way].last_method != HTTP_METHOD_HEAD &&
            (info.code < 100 || (info.code > 199 && info.code != 204 && info.code != 304))
        );

    if (have_body) {
        if (info.set_values & HTTP_LENGTH_SET) {
            http_parser->state[way].phase = BODY;
            http_parser->state[way].remaining_content = info.content_length;
        } else if (info.set_values & HTTP_TRANSFERT_ENCODING_SET) {
            if (info.chunked_encoding) {
                http_parser->state[way].phase = CHUNK_HEAD;
            } else {
                // We will keep looking for header just after this one, hoping for the best.
            }
        } else {    // no length indication
            http_parser->state[way].phase = BODY;
            http_parser->state[way].remaining_content = CONTENT_UP_TO_END;
        }
    } else {
        // We stay in HEAD phase
    }

    // Restart from the end of this header
    streambuf_set_restart(&http_parser->sbuf, way, packet + httphdr_len, false);
    // Report the header
    return proto_parse(NULL, &info.info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
}

/*
 * Parse HTTP Body
 */

static enum proto_parse_status http_parse_body(struct http_parser *http_parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    assert(http_parser->state[way].phase == BODY || http_parser->state[way].phase == CHUNK);

    // In this phase, either we known the content length and we skip it before returning to HEAD phase,
    // or we know that it's going up to the end of socket and we skip eveything,

    if (http_parser->state[way].remaining_content != CONTENT_UP_TO_END) {
        SLOG(LOG_DEBUG, "Parsing body, remaining %zu bytes", http_parser->state[way].remaining_content);
    } else {
        SLOG(LOG_DEBUG, "Parsing body up to end of socket");
    }

    size_t const body_part =    // The part of wire_len that belongs to the current body
        http_parser->state[way].remaining_content == CONTENT_UP_TO_END ||
        http_parser->state[way].remaining_content > wire_len ?
            wire_len :
            http_parser->state[way].remaining_content;
    SLOG(LOG_DEBUG, "%zu bytes of this payload belongs to the body", body_part);

    if (body_part > 0) {    // Ack this body part
        struct http_proto_info info;
        info.set_values = 0;
        http_proto_info_ctor(&info, http_parser, parent, 0, body_part);
        // TODO: choose a subparser according to mime type ?
        (void)proto_parse(NULL, &info.info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
        // What to do with this partial parse status ?
    }

    if (http_parser->state[way].remaining_content != CONTENT_UP_TO_END) {
        assert(http_parser->state[way].remaining_content >= body_part);
        http_parser->state[way].remaining_content -= body_part;
    }

    if (http_parser->state[way].remaining_content == 0) {
        http_parser->state[way].phase =
            http_parser->state[way].phase == BODY ?
                HEAD : CHUNK_HEAD;
        if (body_part == wire_len) return PROTO_OK;
        if (body_part >= cap_len) {
            // Next header was not captured :-(
            return PROTO_TOO_SHORT;
        }
        // Else the (chunk) header is already waiting for us
        streambuf_set_restart(&http_parser->sbuf, way, packet + body_part, false);
    }

    return PROTO_OK;
}

/*
 * Parse HTTP Chunk header
 */

static enum proto_parse_status http_parse_chunk_header(struct http_parser *http_parser, unsigned way, uint8_t const *packet, size_t cap_len, size_t unused_ wire_len)
{
    assert(http_parser->state[way].phase == CHUNK_HEAD);

    SLOG(LOG_DEBUG, "Parsing chunk header");
    // The chunk header is composed of a mere size and optional ";" followed by some garbage up to end of line.
    // So we need at least one line of data
    struct liner liner;
    liner_init(&liner, &delim_lines, (char const *)packet, cap_len);
    if (liner_eof(&liner)) {    // not a single char to read?
        streambuf_set_restart(&http_parser->sbuf, way, packet, true);   // more luck later
        return PROTO_OK;
    }
    char *end;
    unsigned len = strtoul(liner.start, &end, 16);
    if (end == liner.start) {
        return PROTO_PARSE_ERR;
    }
    if (end != liner.start + liner_tok_length(&liner)) {
        streambuf_set_restart(&http_parser->sbuf, way, packet, true);   // more luck later
        return PROTO_OK;
    }
    SLOG(LOG_DEBUG, "Chunk header of size %u", len);

    liner_next(&liner);
    if (len > 0) {
        http_parser->state[way].phase = CHUNK;
        http_parser->state[way].remaining_content = len + 2;    // for the CR+LF following the chunk (the day we will pass the body to a subparser we will need to parse these in next http_parse_chunk_header() call instead).
        streambuf_set_restart(&http_parser->sbuf, way, (const uint8_t *)liner.start, false);
    } else {
        // FIXME: skip chunk trailer, ie all lines up to a blank line.
        http_parser->state[way].phase = HEAD;
        streambuf_set_restart(&http_parser->sbuf, way, (const uint8_t *)liner.start, false);
    }

    return PROTO_OK;
}

/*
 * Proto API
 */

static enum proto_parse_status http_sbuf_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct http_parser *http_parser = DOWNCAST(parser, parser, http_parser);

    // If this is the first time we are called, init c2s_way
    if (http_parser->c2s_way == ~0U) {
        http_parser->c2s_way = way;
        SLOG(LOG_DEBUG, "First packet, init c2s_way to %u", http_parser->c2s_way);
    }

    // Now are we waiting the header, or scanning through body ?
    SLOG(LOG_DEBUG, "Http parser@%p is %s in direction %u", http_parser, http_parser_phase_2_str(http_parser->state[way].phase), way);
    switch (http_parser->state[way].phase) {
        case HEAD:  // In this mode we retry until we manage to parse a header
           return http_parse_header(http_parser, parent, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);
        case CHUNK_HEAD:
           return http_parse_chunk_header(http_parser, way, payload, cap_len, wire_len);
        case BODY:
        case CHUNK:
           return http_parse_body(http_parser, parent, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);
    }

    assert(!"Invalid http parser phase");
    return -1;
}

static enum proto_parse_status http_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct http_parser *http_parser = DOWNCAST(parser, parser, http_parser);

    mutex_lock(&http_parser->mutex);
    enum proto_parse_status const status = streambuf_add(&http_parser->sbuf, parser, parent, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);
    mutex_unlock(&http_parser->mutex);

    return status;
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
        .parse       = http_parse,
        .parser_new  = http_parser_new,
        .parser_del  = http_parser_del,
        .info_2_str  = http_info_2_str,
        .info_addr   = http_info_addr,
        .serialize   = http_serialize,
        .deserialize = http_deserialize,
    };
    proto_ctor(&proto_http_, &ops, "HTTP", PROTO_CODE_HTTP);
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

