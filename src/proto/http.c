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
#include <junkie/proto/tcp.h>
#include <junkie/proto/http.h>
#include <junkie/cpp.h>
#include <junkie/tools/log.h>
#include "proto/httper.h"
#include "proto/liner.h"


static char const Id[] = "$Id: 0477d160214401d1ceeb489639cc1a86210de55d $";

#undef LOG_CAT
#define LOG_CAT proto_http_log_category

LOG_CATEGORY_DEF(proto_http);

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

static void http_proto_info_ctor(struct http_proto_info *info, struct parser *parser, struct proto_info *parent, size_t head_len, size_t payload)
{
    proto_info_ctor(&info->info, parser, parent, head_len, payload);
}

/*
 * Parse
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
    info->content_length = strtoull(liner->start, NULL, 10);
    return 0;
}

static int http_extract_content_type(unsigned unused_ field, struct liner *liner, void *info_)
{
    struct http_proto_info *info = info_;
    info->set_values |= HTTP_MIME_SET;
    copy_token(info->mime_type, sizeof(info->mime_type), liner);
    return 0;
}

static int http_extract_host(unsigned unused_ field, struct liner *liner, void *info_)
{
    struct http_proto_info *info = info_;
    info->set_values |= HTTP_HOST_SET;
    copy_token(info->host, sizeof(info->host), liner);
    return 0;
}

static enum proto_parse_status http_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn, size_t tot_cap_len, uint8_t const *tot_packet)
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
        { "content-length", 14, http_extract_content_length },
        { "content-type",   12, http_extract_content_type },
        { "host",           4,  http_extract_host },
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
    if (0 != httper_parse(&httper, &httphdr_len, packet, cap_len, &info)) {
        return -1;
    }

    assert(httphdr_len <= cap_len);
    http_proto_info_ctor(&info, parser, parent, httphdr_len, wire_len - httphdr_len);

    // TODO: use content type to choose a subparser ?

    return proto_parse(NULL, &info.info, way, packet + httphdr_len, cap_len - httphdr_len, wire_len - httphdr_len, now, okfn, tot_cap_len, tot_packet);
}

/*
 * Init
 */

static struct uniq_proto uniq_proto_http;
struct proto *proto_http = &uniq_proto_http.proto;
static struct port_muxer tcp_port_muxer;

void http_init(void)
{
    log_category_proto_http_init();

    static struct proto_ops const ops = {
        .parse      = http_parse,
        .parser_new = uniq_parser_new,
        .parser_del = uniq_parser_del,
        .info_2_str = http_info_2_str,
        .info_addr  = http_info_addr,
    };
    uniq_proto_ctor(&uniq_proto_http, &ops, "HTTP");
    port_muxer_ctor(&tcp_port_muxer, &tcp_port_muxers, 80, 80, proto_http);
}

void http_fini(void)
{
    port_muxer_dtor(&tcp_port_muxer, &tcp_port_muxers);
    uniq_proto_dtor(&uniq_proto_http);
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

