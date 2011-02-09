// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#include <assert.h>
#include <junkie/cpp.h>
#include <junkie/proto/tcp.h>
#include <junkie/tools/mallocer.h>
#include "lib.h"
#include "proto/http.c"

/*
 * Parse check
 */

static struct parse_test {
    char const *name;
    bool reset_parser;
    char const *packet;
    unsigned nb_expected;    // how many okfn calls this packet should generate
    struct http_proto_info expected[2];
    enum proto_parse_status ret;    // expected return code
} parse_tests [] = {
    {
        .name = "too simple",
        .reset_parser = true,
        .packet = "GET\n",
        .nb_expected = 1,
        .expected = {
            {
                .info = { .head_len = 4, .payload = 0 },
                .set_values = HTTP_METHOD_SET,
                .method = HTTP_METHOD_GET, .code = 0, .content_length = 0,
                .mime_type = "", .host = "", .url = "",
            },
        },
        .ret = PROTO_OK,
    }, {
        .name = "simple",
        .reset_parser = true,
        .packet =
            "GET /\r\n"
            "\r\n",
        .nb_expected = 1,
        .expected = {
            {
                .info = { .head_len = 9, .payload = 0 },
                .set_values = HTTP_METHOD_SET|HTTP_URL_SET,
                .method = HTTP_METHOD_GET, .code = 0, .content_length = 0,
                .mime_type = "", .host = "", .url = "/",
            },
        },
        .ret = PROTO_OK,
    }, {
        .name = "actual GET",
            .reset_parser = true,
            .packet =
                "GET /wiki/UDP HTTP/1.1\015\012"
                "Host: fr.wikipedia.org\015\012"
                "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.5) Gecko/2008121622 Ubuntu/8.04 (hardy) Firefox/3.0.5\015\012"
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\015\012"
                "Accept-Language: en-us,fr;q=0.7,en;q=0.3\015\012"
                "Accept-Encoding: gzip,deflate\015\012"
                "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\015\012"
                "Keep-Alive: 300\015\012"
                "Connection: keep-alive\015\012"
                "Cookie: frwikiUserID=34474; frwikiUserName=Gehel\015\012"
                "If-Modified-Since: Sat, 14 Feb 2009 05:37:35 GMT\015\012"
                "Cache-Control: max-age=0\015\012"
                "\015\012"
                "payload",
            .nb_expected = 1,
            .expected = {
                {
                    .info = { .head_len = 527, .payload = 7 },
                    .set_values = HTTP_METHOD_SET|HTTP_HOST_SET|HTTP_URL_SET,
                    .method = HTTP_METHOD_GET, .code = 0, .content_length = 0,
                    .mime_type = "", .host = "fr.wikipedia.org", .url = "/wiki/UDP",
                },
            },
            .ret = PROTO_OK,
    }, {
        .name = "actual 304",
            .reset_parser = true,
            .packet =
                "HTTP/1.0 304 Not Modified\r\n"
                "Date: Mon, 16 Feb 2009 08:54:28 GMT\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                "Last-Modified: Sat, 14 Feb 2009 05:37:35 GMT\r\n"
                "Age: 14496\r\n"
                "X-Cache: HIT from knsq2.knams.wikimedia.org\r\n"
                "X-Cache-Lookup: HIT from knsq2.knams.wikimedia.org:3128\r\n"
                "X-Cache: MISS from knsq23.knams.wikimedia.org\r\n"
                "X-Cache-Lookup: MISS from knsq23.knams.wikimedia.org:80\r\n"
                "Via: 1.0 knsq2.knams.wikimedia.org:3128 (squid/2.7.STABLE6), 1.0 knsq23.knams.wikimedia.org:80 (squid/2.7.STABLE6)\r\n"
                "Connection: keep-alive\r\n"
                "\r\n",
            .nb_expected = 1,
            .expected = {
                {
                    .info = { .head_len = 510, .payload = 0 },
                    .set_values = HTTP_CODE_SET|HTTP_MIME_SET,
                    .method = 0, .code = 304, .content_length = 0,
                    .mime_type = "text/html; charset=utf-8", .host = "", .url = "",
                },
            },
            .ret = PROTO_OK,
    } , {
        .name = "actual 200",
            .reset_parser = true,
            .packet =
                "HTTP/1.0 200 OK\r\n"
                "Date: Mon, 16 Feb 2009 12:55:58 GMT\r\n"
                "Server: Apache\r\n"
                "Last-Modified: Wed, 28 Jan 2009 01:35:20 GMT\r\n"
                "ETag: \"18b0-46180fc184600\"\r\n"
                "Accept-Ranges: bytes\r\n"
                "Content-Length: 6320\r\n"
                "Cache-Control: max-age=2592000\r\n"
                "Expires: Wed, 18 Mar 2009 12:55:58 GMT\r\n"
                "Content-Type: text/css\r\n"
                "X-Cache: MISS from sq35.wikimedia.org\r\n"
                "X-Cache-Lookup: HIT from sq35.wikimedia.org:3128\r\n"
                "Age: 6\r\n"
                "X-Cache: HIT from knsq25.knams.wikimedia.org\r\n"
                "X-Cache-Lookup: HIT from knsq25.knams.wikimedia.org:3128\r\n"
                "X-Cache: MISS from knsq23.knams.wikimedia.org\r\n"
                "X-Cache-Lookup: HIT from knsq23.knams.wikimedia.org:80\r\n"
                "Via: 1.0 sq35.wikimedia.org:3128 (squid/2.6.STABLE21), 1.0 knsq25.knams.wikimedia.org:3128 (squid/2.7.STABLE6), 1.0 knsq23.knams.wikimedia.org:80 (squid/2.7.STABLE6)\r\n"
                "Connection: keep-alive\r\n"
                "\r\n"
                "123\n",
            .nb_expected = 1,
            .expected = {
                {
                    .info = { .head_len = 781, .payload = 4 },
                    .set_values = HTTP_CODE_SET|HTTP_MIME_SET|HTTP_LENGTH_SET,
                    .method = 0, .code = 200, .content_length = 6320,
                    .mime_type = "text/css", .host = "", .url = "",
                },
            },
            .ret = PROTO_OK,
    }, {
        .name = "fUnnY",
            .reset_parser = true,
            .packet =
                "GET / HTTP/1.1\r\n"
                "Host: \r\n"
                "cOnTenT-Length:123\r\n"
                "\n",
            .nb_expected = 1,
            .expected = {
                {
                    .info = { .head_len = 45, .payload = 0 },
                    .set_values = HTTP_METHOD_SET|HTTP_LENGTH_SET|HTTP_HOST_SET|HTTP_URL_SET,
                    .method = HTTP_METHOD_GET, .code = 0, .content_length = 123,
                    .mime_type = "", .host = "", .url = "/",
                },
            },
            .ret = PROTO_OK,
    }, {
        .name = "erroneous",
            .reset_parser = true,
            .packet = "GE\r\n",
            .nb_expected = 1,
            .expected = {
                {
                    .info = { .head_len = 4, .payload = 0 },
                    .set_values = 0,
                    .method = 0, .code = 0, .content_length = 0,
                    .mime_type = "", .host = "", .url = "",
                },
            },
            .ret = PROTO_PARSE_ERR,
    }, {
        // Now test that the http parser can report properly traffic requiring memory from one packet to the next
        .name = "200 + payload",
            .reset_parser = true,
            .packet =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 32\r\n"
                "Server: gws\r\n"
                "\r\n"
                "0123456789",
            .nb_expected = 1,
            .expected = {
                {
                    .info = { .head_len = 78, .payload = 10 },
                    .set_values = HTTP_CODE_SET|HTTP_LENGTH_SET|HTTP_MIME_SET,
                    .method = 0, .code = 200, .content_length = 32,
                    .mime_type = "text/plain", .host="", .url = "",
                },
            },
            .ret = PROTO_OK,
    }, {
        // Now the continuation of previous packet, followed by another message
        .name = "continuation + 204",
            .reset_parser = false,
            .packet =
                "01234567890123456790\r\n"
                "HTTP/1.1 204 No Content\r\n"
                "Content-Length: 0\r\n"
                "\r\n",
            .nb_expected = 2,
            .expected = {
                {
                    .info = { .head_len = 0, .payload = 22 },
                    .set_values = 0,
                    .method = 0, .code = 0, .content_length = 0,
                    .mime_type = "", .host="", .url = "",
                }, {
                    .info = { .head_len = 46, .payload = 0 },
                    .set_values = HTTP_CODE_SET|HTTP_LENGTH_SET,
                    .method = 0, .code = 204, .content_length = 0,
                    .mime_type = "", .host="", .url = "",
                },
            },
            .ret = PROTO_OK,
    }
};

static unsigned current_test;
static unsigned current_rep;

static int http_info_check(struct proto_info const *info_, size_t unused_ cap_len, uint8_t const unused_ *packet)
{
    assert(current_rep < parse_tests[current_test].nb_expected);

    // Check info against parse_tests[current_test].expected
    struct http_proto_info const *const info = DOWNCAST(info_, info, http_proto_info);
    struct http_proto_info const *const expected = &parse_tests[current_test].expected[current_rep++];
    assert(info->info.head_len == expected->info.head_len);
    assert(info->info.payload == expected->info.payload);
    assert(info->set_values == expected->set_values);
    if (info->set_values & HTTP_METHOD_SET) assert(info->method         == expected->method);
    if (info->set_values & HTTP_CODE_SET)   assert(info->code           == expected->code);
    if (info->set_values & HTTP_LENGTH_SET) assert(info->content_length == expected->content_length);
    if (info->set_values & HTTP_MIME_SET)   assert(0 == strcmp(info->mime_type, expected->mime_type));
    if (info->set_values & HTTP_HOST_SET)   assert(0 == strcmp(info->host,      expected->host));
    if (info->set_values & HTTP_URL_SET)    assert(0 == strcmp(info->url,       expected->url));

    return 0;
}

static void parse_check(void)
{
    struct timeval now;
    timeval_set_now(&now);
    struct parser *parser = proto_http->ops->parser_new(proto_http, &now);
    assert(parser);

    for (current_test = 0; current_test < NB_ELEMS(parse_tests); current_test++) {
        current_rep = 0;
        struct parse_test const *test = parse_tests+current_test;
        printf("Testing packet %s... ", test->name);
        if (test->reset_parser) {
            struct http_parser *http_parser = DOWNCAST(parser, parser, http_parser);
            http_parser->state[0].phase = http_parser->state[1].phase = NONE;
            http_parser->c2s_way = ~0U;
        }
        size_t const len = strlen(test->packet);
        enum proto_parse_status status = http_parse(parser, NULL, 0, (uint8_t *)test->packet, len, len, &now, http_info_check, len, (uint8_t *)test->packet);
        assert(status == test->ret);
        printf("Ok\n");
    }

    parser_unref(parser);
}

void build_url_check(void)
{
    static struct url_test {
        int version;
        char const *server, *host, *url;
        char const *expected;
    } tests[] = {
        { 4, "1.2.3.4", "google.com",    "/index.html", "google.com/index.html" },
        { 4, "1.2.3.4", "google.com",    NULL,          "google.com" },
        { 4, "1.2.3.4", NULL,            NULL,          "1.2.3.4" },
        { 4, "1.2.3.4", NULL,            "/index.html", "1.2.3.4/index.html" },
        { 4, "1.2.3.4", NULL,            "index.html",  "1.2.3.4/index.html" },
        { 4, "1.2.3.4", "google.com:80", "/index.html", "google.com/index.html" },
        { 4, "1.2.3.4", "google.com:80", NULL,          "google.com" },
    };

    for (unsigned t = 0; t < NB_ELEMS(tests); t++) {
        printf("Testing URL %u... ", t);
        struct url_test const *test = tests+t;
        struct ip_addr ip_addr;
        assert(0 == ip_addr_ctor_from_str(&ip_addr, test->server, strlen(test->server), test->version));
        char const *url = http_build_url(&ip_addr, test->host, test->url);
        printf("(%s == %s)... ", test->expected, url);
        assert(0 == strcmp(test->expected, url));
        printf("Ok\n");
    }
}

static bool caplen_reported;
static int caplen_info_check(struct proto_info const unused_ *info, size_t unused_ cap_len, uint8_t const unused_ *packet)
{
    caplen_reported = true;
    return 0;
}

static void caplen_check(void)
{
    // Check that an HTTP message is reported even when capture length is small
    const char msg[] =
        "GET /\r\n\r\n"
        "Maitre corbeau, sur un arbre perche, tenait en son bec un fromage\r\n";

    struct timeval now;
    timeval_set_now(&now);
    struct parser *http_parser = proto_http->ops->parser_new(proto_http, &now);
    assert(http_parser);

    for (size_t cap_len = 9; cap_len < strlen(msg); cap_len++) {
        caplen_reported = false;
        int ret = http_parse(http_parser, NULL, 0, (uint8_t *)msg, cap_len, strlen(msg), &now, caplen_info_check, cap_len, (uint8_t *)msg);
        assert(ret == PROTO_OK);
        assert(caplen_reported);
    }
}

int main(void)
{
    log_init();
    mallocer_init();
    proto_init();
    tcp_init();
    http_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("http_check.log");

    parse_check();
    build_url_check();
    caplen_check();
    stress_check(proto_http);

    http_fini();
    tcp_fini();
    proto_fini();
    mallocer_fini();
    log_fini();
    return EXIT_SUCCESS;
}

