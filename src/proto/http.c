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
#include "junkie/tools/miscmacs.h"
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

struct hook http_head_hook;    // at end of header
struct hook http_body_hook;    // at every piece of body

/*
 * Utilities
 */

static bool end_of_host(char c)
{
    return c == '\0' || c == '/' || c == ':';
}

/* Force the port to appear before the first '/' (or at the end) of thing,
 * or strip it if it's the default http port 80.
 * Note that we also add 443, because we do not include "https://" in the build string.
 * In case port is present in thing don't consider the given port. */
static char const *handle_port(char const *thing, uint16_t const *port)
{
    // locate start and end of port
    char const *colon = thing;
    while (! end_of_host(*colon)) colon ++;
    if (*colon != ':') {
        if (port && *port != 80) {
            return tempstr_printf("%.*s:%"PRIu16"%s", (int)(colon-thing), thing, *port, colon);
        } else {
            return thing;
        }
    }
    char const *start_port = colon + 1;
    while (*start_port == '0') start_port ++;
    char const *end_port = start_port;
    while (! end_of_host(*end_port)) end_port ++;
    if (*end_port == ':') return thing; // ?
    assert(*end_port == '/' || *end_port == '\0');
    // if port is "80" or "0", skip it
    if (
        end_port == start_port ||   // as in "http://host:000/..."
        (
            end_port - start_port == 2 &&   // as in "http://host:80/..."
            start_port[0] == '8' &&
            start_port[1] == '0'
        )
    ) {
        return tempstr_printf("%.*s%s", (int)(colon-thing), thing, end_port);
    } else {
        // just skip the initial 0s
        return tempstr_printf("%.*s:%s", (int)(colon-thing), thing, start_port);
    }
}

static unsigned selector_prefix_length(char const *url, uint16_t *expected_port)
{
    uint16_t ep = 80;
    if (! url) return 0;
    if (
        url[0] != 'h' ||
        url[1] != 't' ||
        url[2] != 't' ||
        url[3] != 'p'
    ) return 0;
    unsigned i = 4;
    if (url[i] == 's') {
        i++;
        ep = 443;
    }
    if (
        url[i++] != ':' ||
        url[i++] != '/' ||
        url[i++] != '/'
    ) return 0;

    // We know the scheme, set expected port
    *expected_port = ep;
    return i;
}

char const *http_build_domain(struct ip_addr const *server, char const *host, char const *url, uint16_t const *port, int version)
{
    char const *src = NULL;
    uint16_t expected_port = 80;
    if (host) {
        src = host;
    } else {
        src += selector_prefix_length(url, &expected_port);
        if (! port) port = &expected_port;
    }

    if (! src) src = (version == 6 ? ip_addr_2_strv6:ip_addr_2_str)(server);

    char const *str = handle_port(src, port);
    // return everything up to first '/'
    char const *end = strchr(str, '/');
    if (end) {
        return tempstr_printf("%.*s", (int)(end-str), str);
    } else {
        return str;
    }
}

// We strip the port only when it's 80. Otherwise we add it.
char const *http_build_url(struct ip_addr const *server, char const *host, char const *url, uint16_t const *port)
{
    uint16_t expected_port = 80;
    unsigned sel_len = selector_prefix_length(url, &expected_port);
    if (! port) port = &expected_port;
    if (sel_len > 0) {
        return handle_port(url + sel_len, port);
    } else {    // url does not include host
        char *str = tempstr();
        snprintf(str, TEMPSTR_SIZE, "%s%s%s",
            http_build_domain(server, host, url, port, 4),
            !url || url[0] == '/' ? "" : "/",
            url ? url : "");
        return str;
    }
}

/*
 * Parsing
 */

struct http_parser {
    struct parser parser;
    struct streambuf sbuf;
    struct http_state {
        unsigned pkts;      // number of pkts in this message (so far)
        enum http_phase {
            HEAD,           // while waiting for/scanning header
            BODY,           // while scanning body
            CHUNK_HEAD,     // while scanning a chunk header
            CHUNK,          // while scanning a body chunk
            CHUNK_CRLF,     // while scanning the trailing CRLF of a body chunk
            CHUNK_TRAILER,  // while scanning the trailing header of a chunked body
        } phase;
        struct timeval first;   // first packet for this message
        struct timeval last;    // last packet we received (only set if first is set)
#       define CONTENT_UP_TO_END ((size_t)((ssize_t)-1))
        size_t remaining_content;   // nb bytes before next header (or (ssize_t)-1 if unknown). Only relevant when phase=BODY|CHUNK.
        // Store the last query command, to be taken it into account to skip body in answer to HEADs
        enum http_method last_method;
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
        case CHUNK_CRLF: return "scanning chunk trailing CRLF";
        case CHUNK_TRAILER: return "scanning chunked-body trailer";
    }
    assert(!"Unknown HTTP pase");
}


static void http_parser_reset_phase(struct http_parser *http_parser, unsigned way, enum http_phase phase)
{
    SLOG(LOG_DEBUG, "Reset phase for direction %u to %s", way, http_parser_phase_2_str(phase));

    http_parser->state[way].phase = phase;
    /* Note that we do not init first to now because we can create the parser
     * before receiving the first packet (in case of conntracking for
     * instance.) */
    if (phase == HEAD) {
        http_parser->state[way].pkts = 0;
        timeval_reset(&http_parser->state[way].first);
    }
}

static parse_fun http_sbuf_parse;
static int http_parser_ctor(struct http_parser *http_parser, struct proto *proto)
{
    SLOG(LOG_DEBUG, "Construct HTTP parser@%p", http_parser);

    assert(proto == proto_http);
    if (0 != parser_ctor(&http_parser->parser, proto)) return -1;
    for (unsigned way = 0; way <= 1; way++) {
        http_parser_reset_phase(http_parser, way, HEAD);
        http_parser->state[way].last_method = UNSET;
    }
#   define HTTP_MAX_HDR_SIZE 10000   // in bytes
    if (0 != streambuf_ctor(&http_parser->sbuf, http_sbuf_parse, HTTP_MAX_HDR_SIZE)) return -1;

    return 0;
}

static struct parser *http_parser_new(struct proto *proto)
{
    struct http_parser *http_parser = objalloc_nice(sizeof(*http_parser), "HTTP parsers");
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
    return tempstr_printf("%s, method=%s, code=%s, content_length=%s, transfert_encoding=%s, mime_type=%s, host=%s, user_agent=%s, referrer=%s, server=%s, orig_ip=%s, url=%s, pkts=%u%s%s",
        proto_info_2_str(info_),
        HTTP_IS_QUERY(info)                  ? http_method_2_str(info->method)            : "unset",
        info->set_values & HTTP_CODE_SET     ? tempstr_printf("%u", info->code)           : "unset",
        info->set_values & HTTP_LENGTH_SET   ? tempstr_printf("%u", info->content_length) : "unset",
        info->set_values & HTTP_TRANSFERT_ENCODING_SET ?
                                               (info->chunked_encoding ? "chunked":"set") : "unset",
        info->set_values & HTTP_MIME_SET     ? info->strs+info->mime_type                 : "unset",
        info->set_values & HTTP_HOST_SET     ? info->strs+info->host                      : "unset",
        info->set_values & HTTP_USER_AGENT_SET ?
                                               info->strs+info->user_agent                : "unset",
        info->set_values & HTTP_REFERRER_SET ? info->strs+info->referrer                  : "unset",
        info->set_values & HTTP_SERVER_SET   ? info->strs+info->server                    : "unset",
        info->set_values & HTTP_ORIG_CLIENT_SET ?
                                               ip_addr_2_str(&info->orig_client)          : "unset",
        info->set_values & HTTP_URL_SET      ? info->strs+info->url                       : "unset",
        info->pkts,
        info->ajax                           ? ", ajax":"",
        info->compressed                     ? ", compressed":"");
}

static void http_proto_info_ctor(struct http_proto_info *http, struct timeval const *first, unsigned pkts)
{
    http->set_values = 0;
    http->free_strs = 0;
    http->pkts = pkts;
    http->first = *first;
    http->ajax = false; // until proven otherwise
    http->compressed = false;
    // http->info initialized later
}

/*
 * Parse HTTP header
 */

static unsigned copy_token_chopped(char *dest, size_t dest_sz, struct liner *liner)
{
    if (liner->tok_size >= 2) {
        if (liner->start[0] == '\13' && liner->start[1] == '\10') {
            liner_skip(liner, 2);
        }
    }

    while (
        liner->tok_size > 0 &&
        (liner->start[0] == ' ' || liner->start[0] == '\t')
    ) liner_skip(liner, 1);

    return copy_token(dest, dest_sz, liner);
}

static void copy_token_in_strs(struct http_proto_info *info, unsigned *offset, struct liner *liner)
{
    if (info->free_strs >= sizeof(info->strs)) {
        *offset = sizeof(info->strs)-1; // points to the last '\0'
    } else {
        *offset = info->free_strs;
        info->free_strs += 1 + copy_token_chopped(info->strs + info->free_strs, sizeof(info->strs) - info->free_strs, liner);
    }
}

static int http_set_method(unsigned cmd, struct liner *liner, void *info_)
{
    struct http_proto_info *info = info_;
    info->set_values |= HTTP_METHOD_SET;
    info->method = cmd;
    // URL is the next token
    if (! liner_eof(liner)) {
        info->set_values |= HTTP_URL_SET;
        copy_token_in_strs(info, &info->url, liner);
        /* The URL is what we fetch first and we risk filling up the whole strs buffer
         * right from the start. To avoid this, limit what we use for URL to this amount: */
        assert(info->free_strs >= info->url);
        unsigned const url_size = info->free_strs - info->url;
        if (url_size > HTTP_MAX_URL_SIZE) {
            info->free_strs = info->url + HTTP_MAX_URL_SIZE;
            info->strs[info->free_strs - 1] = '\0';
        }
    }
    return 0;
}

// TODO: some boolean EXT_PARAMS to disable fetching of each HTTP fields

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
    copy_token_in_strs(info, &info->mime_type, liner);
    return 0;
}

static int http_extract_transfert_encoding(unsigned unused_ field, struct liner *liner, void *info_)
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
    copy_token_in_strs(info, &info->host, liner);
    return 0;
}

static int http_extract_user_agent(unsigned unused_ field, struct liner *liner, void *info_)
{
    struct http_proto_info *info = info_;
    info->set_values |= HTTP_USER_AGENT_SET;
    copy_token_in_strs(info, &info->user_agent, liner);
    return 0;
}

static int http_extract_referrer(unsigned unused_ field, struct liner *liner, void *info_)
{
    struct http_proto_info *info = info_;
    info->set_values |= HTTP_REFERRER_SET;
    copy_token_in_strs(info, &info->referrer, liner);
    return 0;
}

static int http_extract_server(unsigned unused_ field, struct liner *liner, void *info_)
{
    struct http_proto_info *info = info_;
    info->set_values |= HTTP_SERVER_SET;
    copy_token_in_strs(info, &info->server, liner);
    return 0;
}

static int http_extract_requested_with(unsigned unused_ field, struct liner *liner, void *info_)
{
    struct http_proto_info *info = info_;
    info->ajax = 0 == strncasecmp(liner->start, "XMLHttpRequest", 14);
    if (info->ajax) SLOG(LOG_DEBUG, "X-Requested-with looks like AJAX");
    return 0;
}

static int http_extract_accept(unsigned unused_ field, struct liner *liner, void *info_)
{
    struct http_proto_info *info = info_;
    info->ajax = 0 == strncasecmp(liner->start, "application/json", 16);
    if (info->ajax) SLOG(LOG_DEBUG, "Accept looks like AJAX");
    return 0;
}

static int http_extract_origin(unsigned unused_ field, struct liner unused_ *liner, void *info_)
{
    struct http_proto_info *info = info_;
    info->ajax = true;
    SLOG(LOG_DEBUG, "Origin field present -> AJAX");
    return 0;
}

static int http_extract_content_encoding(unsigned unused_ field, struct liner *liner, void *info_)
{
    struct http_proto_info *info = info_;
    info->compressed =
        0 == strncasecmp(liner->start, "gzip", 4) ||
        0 == strncasecmp(liner->start, "compress", 8) ||
        0 == strncasecmp(liner->start, "deflate", 7);
    return 0;
}

static int http_extract_client_ip(unsigned unused_ field, struct liner *liner, void *info_)
{
    struct http_proto_info *info = info_;
    /* We are supposed to have a list of IPs, coma separated, first one being
     * the original client (Cf. http://en.wikipedia.org/wiki/X-Forwarded-For) */

    // if this list comes in several header lines, keep only the first one
    if (info->set_values & HTTP_ORIG_CLIENT_SET) return 0;

    // look for end of IP
    size_t const tot_len = liner_tok_length(liner);
    size_t ip_len;
    for (ip_len = 0; ip_len < tot_len; ip_len++) {
        uint8_t const c = liner->start[ip_len];
        if (',' == c || ' ' == c) break;
    }

    if (0 == ip_addr_ctor_from_str(&info->orig_client, liner->start, ip_len, 0)) {
        info->set_values |= HTTP_ORIG_CLIENT_SET;
    }
    return 0;
}

static enum proto_parse_status http_parse_header(struct http_parser *http_parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    assert(http_parser->state[way].phase == HEAD);

    // Sanity checks + Parse
    static struct httper_command const commands[] = {
        [HTTP_METHOD_GET]      = { STRING_AND_LEN("GET"),      http_set_method },
        [HTTP_METHOD_HEAD]     = { STRING_AND_LEN("HEAD"),     http_set_method },
        [HTTP_METHOD_POST]     = { STRING_AND_LEN("POST"),     http_set_method },
        [HTTP_METHOD_CONNECT]  = { STRING_AND_LEN("CONNECT"),  http_set_method },
        [HTTP_METHOD_PUT]      = { STRING_AND_LEN("PUT"),      http_set_method },
        [HTTP_METHOD_OPTIONS]  = { STRING_AND_LEN("OPTIONS"),  http_set_method },
        [HTTP_METHOD_TRACE]    = { STRING_AND_LEN("TRACE"),    http_set_method },
        [HTTP_METHOD_DELETE]   = { STRING_AND_LEN("DELETE"),   http_set_method },
        [HTTP_METHOD_DELETE+1] = { STRING_AND_LEN("HTTP/1.1"), http_extract_code },
        [HTTP_METHOD_DELETE+2] = { STRING_AND_LEN("HTTP/1.0"), http_extract_code },
    };
    static struct httper_field const fields[] = {
        { STRING_AND_LEN("content-length"),    http_extract_content_length },
        { STRING_AND_LEN("content-type"),      http_extract_content_type },
        { STRING_AND_LEN("transfer-encoding"), http_extract_transfert_encoding },
        { STRING_AND_LEN("host"),              http_extract_host },
        { STRING_AND_LEN("user-agent"),        http_extract_user_agent },
        { STRING_AND_LEN("referrer"),          http_extract_referrer },
        { STRING_AND_LEN("referer"),           http_extract_referrer },
        { STRING_AND_LEN("server"),            http_extract_server },
        { STRING_AND_LEN("x-requested-with"),  http_extract_requested_with },
        { STRING_AND_LEN("accept"),            http_extract_accept },
        { STRING_AND_LEN("origin"),            http_extract_origin },
        { STRING_AND_LEN("content-encoding"),  http_extract_content_encoding },
        { STRING_AND_LEN("x-forwarded-for"),   http_extract_client_ip },
        { STRING_AND_LEN("x-real-ip"),         http_extract_client_ip },
    };
    static struct httper const httper = {
        .nb_commands = NB_ELEMS(commands),
        .commands = commands,
        .nb_fields = NB_ELEMS(fields),
        .fields = fields
    };

    struct http_proto_info info;
    http_proto_info_ctor(&info, &http_parser->state[way].first, http_parser->state[way].pkts);    // we init the proto_info once validated

    size_t httphdr_len;
    enum proto_parse_status status = httper_parse(&httper, &httphdr_len, packet, cap_len, &info);
    if (status == PROTO_PARSE_ERR) return PROTO_PARSE_ERR;

    // Handle short capture
    if (status == PROTO_TOO_SHORT) {
        // Are we going to receive the end eventually?
        if (wire_len == cap_len) {
            SLOG(LOG_DEBUG, "Incomplete HTTP headers, will restart later");
            // So header end must be in next packet(s)
            status = proto_parse(NULL, parent, way, NULL, 0, 0, now, tot_cap_len, tot_packet);    // ack what we had so far
            streambuf_set_restart(&http_parser->sbuf, way, packet, true);   // retry later with (hopefully) complete header this time
            return PROTO_OK;
        } else {
            // No, the header was truncated. We want to report as much as we can.
            proto_info_ctor(&info.info, &http_parser->parser, parent, cap_len, 0);
            // call hooks on header (for tx hooks we'd rather have pointers on message than pointer to packet)
            hook_subscribers_call(&http_head_hook, &info.info, cap_len, packet, now);
            // We are going to look for another header at the start of the next packet, hoping for the best.
            http_parser_reset_phase(http_parser, way, HEAD);
            // continuation
            return proto_parse(NULL, &info.info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
        }
    }

    // Save some values into our http_parser
    http_parser->state[way].last_method =
        HTTP_IS_QUERY(&info) ? info.method : UNSET;

    // Ajax can also be guessed from URL
    if (!info.ajax && info.set_values & HTTP_URL_SET) {
        // Detects JSONP (cf. http://en.wikipedia.org/wiki/JSONP)
        info.ajax = strcasestr(info.strs+info.url, "?jsonp=") ||
                    strcasestr(info.strs+info.url, "&jsonp=") ||
                    strcasestr(info.strs+info.url, "?callback=") ||
                    strcasestr(info.strs+info.url, "&callback=");
        if (info.ajax) SLOG(LOG_DEBUG, "URL looks like AJAX");
    }

    /* What payload should we set? the one advertised? Or the payload of this header (ie 0),
     * and then let the body parser report other proto_info with head_len=0 and payload set?
     * will be definitively FIXED once we ditch this reporting policy for a hook based approach. */
    proto_info_ctor(&info.info, &http_parser->parser, parent, httphdr_len, 0);

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
    info.have_body =
        (
            HTTP_IS_QUERY(&info) &&
            (info.set_values & (HTTP_LENGTH_SET | HTTP_TRANSFERT_ENCODING_SET))
        ) || (
            (info.set_values & HTTP_CODE_SET) &&
            http_parser->state[!way].last_method != HTTP_METHOD_HEAD &&
            (info.code < 100 || (info.code > 199 && info.code != 204 && info.code != 304))
        );

    if (info.set_values & HTTP_LENGTH_SET && 0 == info.content_length) {
        /* If we restart then the update_body callback won't be called untill there are more data to parse.
         * Better let the users know that there won't be any body this time. */
        info.have_body = false;
    }

    if (info.have_body) {
        if (info.set_values & HTTP_LENGTH_SET) {
            http_parser_reset_phase(http_parser, way, BODY);
            http_parser->state[way].remaining_content = info.content_length;
        } else if (info.set_values & HTTP_TRANSFERT_ENCODING_SET) {
            if (info.chunked_encoding) {
                http_parser_reset_phase(http_parser, way, CHUNK_HEAD);
            } else {
                // We will keep looking for header just after this one, hoping for the best.
            }
        } else {    // no length indication
            http_parser_reset_phase(http_parser, way, BODY);
            http_parser->state[way].remaining_content = CONTENT_UP_TO_END;
        }
    } else {
        // We stay in HEAD phase (but we reset msg nonetheless)
        http_parser_reset_phase(http_parser, way, HEAD);
    }

    // call hooks on header
    hook_subscribers_call(&http_head_hook, &info.info, httphdr_len, packet, now);

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

    /* Build the info structure with body_part (payload) as the only useful information */
    struct http_proto_info info;
    http_proto_info_ctor(&info, &http_parser->state[way].first, http_parser->state[way].pkts);
    proto_info_ctor(&info.info, &http_parser->parser, parent, 0, body_part);
    // advertise this body part
    hook_subscribers_call(&http_body_hook, &info.info, MIN(cap_len, body_part), packet, now);

    if (body_part > 0) {    // Ack this body part
        // TODO: choose a subparser according to mime type ?
        (void)proto_parse(NULL, &info.info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
        // What to do with this partial parse status ?
    }

    if (http_parser->state[way].remaining_content != CONTENT_UP_TO_END) {
        assert(http_parser->state[way].remaining_content >= body_part);
        http_parser->state[way].remaining_content -= body_part;
        SLOG(LOG_DEBUG, "%zu bytes of body left", http_parser->state[way].remaining_content);
    }

    /* FIXME: if remaining_content == CONTENT_UP_TO_END, we won't be able to advertize
     * the end of body. We could either:
     * - subscribe also to some tcp_close event and use that instead
     * - have TCP call it's parser with 0 payload to signal the end of stream */

    if (http_parser->state[way].remaining_content == 0) {
        if (http_parser->state[way].phase == BODY) {
            http_parser_reset_phase(http_parser, way, HEAD);
        } else {
            http_parser_reset_phase(http_parser, way, CHUNK_CRLF);
        }

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

    // We won't be able to parse anything if we lack these bytes
    if (cap_len == 0 && wire_len > 0) return PROTO_TOO_SHORT;   // nothing to report in this case

    // The chunk header is composed of a mere size and optional ";" followed by some garbage up to end of line.
    // So we need at least one line of data
    struct liner liner;
    liner_init(&liner, &delim_lines, (char const *)packet, cap_len);
    if (liner_eof(&liner)) {    // not a single char to read?
        streambuf_set_restart(&http_parser->sbuf, way, packet, true);   // more luck later
        return PROTO_OK;
    }
    char const *end;
    unsigned len = liner_strtoull(&liner, &end, 16);
    if (end == liner.start) {
        return PROTO_PARSE_ERR;
    }
    SLOG(LOG_DEBUG, "Chunk header of size %u", len);

    liner_next(&liner);
    if (len > 0) {
        http_parser_reset_phase(http_parser, way, CHUNK);
        http_parser->state[way].remaining_content = len;    // for the CR+LF following the chunk (the day we will pass the body to a subparser we will need to parse these in next http_parse_chunk_header() call instead).
        streambuf_set_restart(&http_parser->sbuf, way, (const uint8_t *)liner.start, false);
    } else {
        http_parser_reset_phase(http_parser, way, CHUNK_TRAILER);
        streambuf_set_restart(&http_parser->sbuf, way, (const uint8_t *)liner.start, false);
    }

    return PROTO_OK;
}

static enum proto_parse_status http_parse_chunk_crlf(struct http_parser *http_parser, unsigned way, uint8_t const *packet, size_t cap_len, size_t unused_ wire_len)
{
    assert(http_parser->state[way].phase == CHUNK_CRLF);

    SLOG(LOG_DEBUG, "Parsing chunk trailing CRLF");

    if (wire_len < 2) {
        streambuf_set_restart(&http_parser->sbuf, way, packet, true);   // more luck later
        return PROTO_OK;
    }

    // check these are the expected CR LF
    if (cap_len >= 1 && packet[0] != '\r') {
invalid:
        SLOG(LOG_DEBUG, "Invalid end of chunk headers (should be CRLF but have %02x %02x)", packet[0], cap_len >= 2 ? packet[1]:0);
        return PROTO_PARSE_ERR;
    }
    if (cap_len >= 2 && packet[1] != '\n') goto invalid;

    // Swallow these 2 bytes
    http_parser_reset_phase(http_parser, way, CHUNK_HEAD);

    if (2 == wire_len) return PROTO_OK;

    if (cap_len > 2) {
        streambuf_set_restart(&http_parser->sbuf, way, packet + 2, false);
    } else {
        // Next header was not captured :-(
        return PROTO_TOO_SHORT;
    }

    return PROTO_OK;
}

// Skip any lines up to an empty one (signaling end of trailer)
static enum proto_parse_status http_parse_chunk_trailer(struct http_parser *http_parser, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len)
{
    assert(http_parser->state[way].phase == CHUNK_TRAILER);

    SLOG(LOG_DEBUG, "Parsing chunk trailer");

    // We won't be able to parse anything if we lack these bytes
    if (cap_len < 2 && wire_len > cap_len) return PROTO_TOO_SHORT;   // nothing to report in this case

    struct liner liner;
    liner_init(&liner, &delim_lines, (char const *)packet, cap_len);
    if (liner_eof(&liner)) {    // not a single char to read?
        streambuf_set_restart(&http_parser->sbuf, way, packet, true);   // more luck later
        return PROTO_OK;
    }

    liner_next(&liner);
    streambuf_set_restart(&http_parser->sbuf, way, (const uint8_t *)liner.start, false);

    SLOG(LOG_DEBUG, "Chunk trailer line of length %zu", liner_tok_length(&liner));
    if (liner_tok_length(&liner) == 0) {    // hourra, get out of here!
        http_parser_reset_phase(http_parser, way, HEAD);
    }

    return PROTO_OK;
}

/*
 * Proto API
 */

static enum proto_parse_status http_sbuf_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct http_parser *http_parser = DOWNCAST(parser, parser, http_parser);

    if (! timeval_is_set(&http_parser->state[way].first)) {
        if (payload) {   // a gap does not count as the start of a message
            SLOG(LOG_DEBUG, "Setting first TS of HTTP@%p to %s", parser, timeval_2_str(now));
            http_parser->state[way].first = *now;
        }
    }
    http_parser->state[way].last = *now;
    http_parser->state[way].pkts ++;

    // Now are we waiting the header, or scanning through body ?
    SLOG(LOG_DEBUG, "Http parser@%p is %s in direction %u", http_parser, http_parser_phase_2_str(http_parser->state[way].phase), way);
    switch (http_parser->state[way].phase) {
        case HEAD:  // In this mode we retry until we manage to parse a header
           return http_parse_header(http_parser, parent, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);
        case CHUNK_HEAD:
           return http_parse_chunk_header(http_parser, way, payload, cap_len, wire_len);
        case CHUNK_CRLF:
           return http_parse_chunk_crlf(http_parser, way, payload, cap_len, wire_len);
        case BODY:
        case CHUNK:
           return http_parse_body(http_parser, parent, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);
        case CHUNK_TRAILER:
           return http_parse_chunk_trailer(http_parser, way, payload, cap_len, wire_len);
    }

    assert(!"Invalid http parser phase");
    return -1;
}

static enum proto_parse_status http_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct http_parser *http_parser = DOWNCAST(parser, parser, http_parser);
    return streambuf_add(&http_parser->sbuf, parser, parent, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);
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

    hook_ctor(&http_head_hook, "HTTP head");
    hook_ctor(&http_body_hook, "HTTP body");

    static struct proto_ops const ops = {
        .parse       = http_parse,
        .parser_new  = http_parser_new,
        .parser_del  = http_parser_del,
        .info_2_str  = http_info_2_str,
        .info_addr   = http_info_addr
    };
    proto_ctor(&proto_http_, &ops, "HTTP", PROTO_CODE_HTTP);
    port_muxer_ctor(&tcp_port_muxer, &tcp_port_muxers, 80, 80, proto_http);
}

void http_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    port_muxer_dtor(&tcp_port_muxer, &tcp_port_muxers);
    hook_dtor(&http_body_hook);
    hook_dtor(&http_head_hook);
    proto_dtor(&proto_http_);
#   endif

    log_category_proto_http_fini();
}
