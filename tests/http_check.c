// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#undef NDEBUG
#include <assert.h>
#include <junkie/cpp.h>
#include <junkie/proto/cap.h>
#include <junkie/proto/eth.h>
#include <junkie/proto/ip.h>
#include <junkie/proto/tcp.h>
#include <junkie/tools/ext.h>
#include <junkie/tools/objalloc.h>
#include <junkie/proto/pkt_wait_list.h>
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
        // Test that a simple GET is parsed allright.
        .name = "too simple",
        .reset_parser = true,
        .packet = "GET\n",
        .nb_expected = 1,
        .expected = {
            {
                .info = { .head_len = 4, .payload = 0 },
                .set_values = HTTP_METHOD_SET,
                .method = HTTP_METHOD_GET, .code = 0,
                .content_length = 0, .chunked_encoding = false,
                .mime_type = 0, .host = 0, .user_agent = 0, .server = 0, .url = 0,
                .free_strs = 0, .strs = "",
            },
        },
        .ret = PROTO_OK,
    }, {
        // Another sample of ancestral http that we'd like to understand
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
                .method = HTTP_METHOD_GET, .code = 0,
                .content_length = 0,.chunked_encoding = false,
                .mime_type = 0, .host = 0, .user_agent = 0, .server = 0, .url = 0,
                .free_strs = 2, .strs = "/",
            },
        },
        .ret = PROTO_OK,
    }, {
        // Test that an actual GET is understood
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
                "\015\012",
            .nb_expected = 1,
            .expected = {
                {
                    .info = { .head_len = 527, .payload = 0 },
                    .set_values = HTTP_METHOD_SET|HTTP_HOST_SET|HTTP_URL_SET|HTTP_USER_AGENT_SET,
                    .method = HTTP_METHOD_GET, .code = 0,
                    .content_length = 0, .chunked_encoding = false,
                    .mime_type = 0, .host = 10, .user_agent = 27, .server = 0, .url = 0,
                    .free_strs = 130,
                    .strs =
                        "/wiki/UDP\0"
                        "fr.wikipedia.org\0"
                        "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.5) Gecko/2008121622 Ubuntu/8.04 (hardy) Firefox/3.0.5\0",
                },
            },
            .ret = PROTO_OK,
    }, {
        // Actual response
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
                    .method = 0, .code = 304,
                    .content_length = 0, .chunked_encoding = false,
                    .mime_type = 0, .host = 0, .user_agent = 0, .server = 0, .url = 0,
                    .free_strs = 25,
                    .strs = "text/html; charset=utf-8"
                },
            },
            .ret = PROTO_OK,
    } , {
        // Actual response with payload
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
            .nb_expected = 2,
            .expected = {
                {
                    .info = { .head_len = 781, .payload = 0 },
                    .set_values = HTTP_CODE_SET|HTTP_MIME_SET|HTTP_LENGTH_SET|HTTP_SERVER_SET,
                    .method = 0, .code = 200,
                    .content_length = 6320, .chunked_encoding = false,
                    .mime_type = 0, .host = 0, .user_agent = 0, .server = 9, .url = 0,
                    .free_strs = 16,
                    .strs = "text/css\0Apache"
                }, {
                    .info = { .head_len = 0, .payload = 4 },
                    .set_values = 0,
                    .method = 0, .code = 0,
                    .content_length = 0, .chunked_encoding = false,
                    .mime_type = 0, .host = 0, .user_agent = 0, .server = 0, .url = 0,
                    .free_strs = 0,
                    .strs = ""
                }
            },
            .ret = PROTO_OK,
    }, {
        // Badly formated headers which should be parsed anyway.
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
                    .method = HTTP_METHOD_GET, .code = 0,
                    .content_length = 123, .chunked_encoding = false,
                    .mime_type = 0, .host = 2, .user_agent = 0, .server = 0, .url = 0,
                    .free_strs = 3, // beware: empty host is still present!
                    .strs = "/\0"
                },
            },
            .ret = PROTO_OK,
    }, {
        // Wrong request
        .name = "erroneous",
            .reset_parser = true,
            .packet = "GE\r\n",
            .nb_expected = 1,
            .expected = {
                {
                    .info = { .head_len = 4, .payload = 0 },
                    .set_values = 0,
                    .method = 0, .code = 0,
                    .content_length = 0, .chunked_encoding = false,
                    .mime_type = 0, .host = 0, .user_agent = 0, .server = 0, .url = 0,
                    .free_strs = 0, .strs = ""
                },
            },
            .ret = PROTO_PARSE_ERR,
    }, {
        // Now test that the HTTP parser can report properly traffic requiring memory from one packet to the next
        .name = "200 + payload",
            .reset_parser = true,
            .packet =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 32\r\n"
                "Server: gws\r\n"
                "\r\n"
                "0123456789",
            .nb_expected = 2,
            .expected = {
                {
                    .info = { .head_len = 78, .payload = 0 },
                    .set_values = HTTP_CODE_SET|HTTP_LENGTH_SET|HTTP_MIME_SET|HTTP_SERVER_SET,
                    .method = 0, .code = 200,
                    .content_length = 32, .chunked_encoding = false,
                    .mime_type = 0, .host = 0, .user_agent = 0, .server = 11, .url = 0,
                    .free_strs = 15,
                    .strs = "text/plain\0gws"
                }, {
                    .info = { .head_len = 0, .payload = 10 },
                    .set_values = 0,
                    .method = 0, .code = 0,
                    .content_length = 0, .chunked_encoding = false,
                    .mime_type = 0, .host = 0, .user_agent = 0, .server = 0, .url = 0,
                    .free_strs = 0,
                    .strs = ""
                }
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
                    .method = 0, .code = 0,
                    .content_length = 0, .chunked_encoding = false,
                    .mime_type = 0, .host = 0, .user_agent = 0, .server = 0, .url = 0,
                    .free_strs = 0, .strs = "",
                }, {
                    .info = { .head_len = 46, .payload = 0 },
                    .set_values = HTTP_CODE_SET|HTTP_LENGTH_SET,
                    .method = 0, .code = 204,
                    .content_length = 0, .chunked_encoding = false,
                    .mime_type = 0, .host = 0, .user_agent = 0, .server = 0, .url = 0,
                    .free_strs = 0, .strs = "",
                },
            },
            .ret = PROTO_OK,
    }
};

static unsigned current_test;
static unsigned current_rep;

static void http_info_check(struct proto_subscriber unused_ *s, struct proto_info const *info_, size_t unused_ cap_len, uint8_t const unused_ *packet, struct timeval const unused_ *now)
{
    assert(current_rep < parse_tests[current_test].nb_expected);

    // Check info against parse_tests[current_test].expected
    struct http_proto_info const *const info = DOWNCAST(info_, info, http_proto_info);
    struct http_proto_info const *const expected = &parse_tests[current_test].expected[current_rep++];
    assert(info->info.head_len == expected->info.head_len);
    assert(info->info.payload == expected->info.payload);
    assert(info->set_values == expected->set_values);
    if (info->set_values & HTTP_METHOD_SET)     assert(info->method         == expected->method);
    if (info->set_values & HTTP_CODE_SET)       assert(info->code           == expected->code);
    if (info->set_values & HTTP_LENGTH_SET)     assert(info->content_length == expected->content_length);
    if (info->set_values & HTTP_MIME_SET)       assert(0 == strcmp(info->strs+info->mime_type,  expected->strs+expected->mime_type));
    if (info->set_values & HTTP_USER_AGENT_SET) assert(0 == strcmp(info->strs+info->user_agent, expected->strs+expected->user_agent));
    if (info->set_values & HTTP_HOST_SET)       assert(0 == strcmp(info->strs+info->host,       expected->strs+expected->host));
    if (info->set_values & HTTP_SERVER_SET)     assert(0 == strcmp(info->strs+info->server,     expected->strs+expected->server));
    if (info->set_values & HTTP_URL_SET)        assert(0 == strcmp(info->strs+info->url,        expected->strs+expected->url));
    assert(info->free_strs == expected->free_strs);
}

static void http_parser_reset(struct parser *parser)
{
    struct http_parser *http_parser = DOWNCAST(parser, parser, http_parser);
    http_parser->state[0].phase = http_parser->state[1].phase = HEAD;
    http_parser->state[0].last_method = http_parser->state[1].last_method = ~0U;
}

static void parse_check(void)
{
    struct timeval now;
    timeval_set_now(&now);
    struct parser *parser = proto_http->ops->parser_new(proto_http);
    assert(parser);
    struct proto_subscriber sub;
    hook_subscriber_ctor(&proto_http->hook, &sub, http_info_check);   // receive all HTTP messages (including for payload)

    for (current_test = 0; current_test < NB_ELEMS(parse_tests); current_test++) {
        current_rep = 0;
        struct parse_test const *test = parse_tests+current_test;
        printf("Testing packet %s... ", test->name);
        if (test->reset_parser) {
            http_parser_reset(parser);
        }
        size_t const len = strlen(test->packet);
        enum proto_parse_status status = http_parse(parser, NULL, 0, (uint8_t *)test->packet, len, len, &now, len, (uint8_t *)test->packet);
        assert(status == test->ret);
        printf("Ok\n");
    }

    hook_subscriber_dtor(&proto_http->hook, &sub);
    parser_unref(&parser);
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
static void caplen_info_check(struct proto_subscriber unused_ *s, struct proto_info const unused_ *info, size_t unused_ cap_len, uint8_t const unused_ *packet, struct timeval const unused_ *now)
{
    caplen_reported = true;
}

static void caplen_check(void)
{
    // Check that an HTTP message is reported even when capture length is small
#   define HEADERS "HTTP/1.1 200 OK\r\n\r\n"
#   define CONTENT "Maitre corbeau, sur un arbre perche, tenait en son bec un fromage\r\n"
    const char msg[] = HEADERS CONTENT;

    struct timeval now;
    timeval_set_now(&now);
    struct parser *http_parser = proto_http->ops->parser_new(proto_http);
    assert(http_parser);
    struct proto_subscriber sub;
    hook_subscriber_ctor(&pkt_hook, &sub, caplen_info_check);

    for (size_t cap_len = strlen(HEADERS); cap_len < strlen(msg); cap_len++) {
        caplen_reported = false;
        http_parser_reset(http_parser);
        int ret = http_parse(http_parser, NULL, 0, (uint8_t *)msg, cap_len, strlen(msg), &now, cap_len, (uint8_t *)msg);
        assert(ret == PROTO_OK);
        assert(caplen_reported);
    }

    hook_subscriber_dtor(&pkt_hook, &sub);
}

int main(void)
{
    log_init();
    ext_init();
    objalloc_init();
    streambuf_init();
    proto_init();
    pkt_wait_list_init();
    ref_init();
    cap_init();
    eth_init();
    ip_init();
    ip6_init();
    tcp_init();
    http_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("http_check.log");

    parse_check();
    build_url_check();
    caplen_check();
    stress_check(proto_http);

    doomer_stop();
    http_fini();
    tcp_fini();
    ip6_fini();
    ip_fini();
    eth_fini();
    cap_fini();
    ref_fini();
    pkt_wait_list_fini();
    proto_fini();
    streambuf_fini();
    objalloc_fini();
    ext_fini();
    log_fini();
    return EXIT_SUCCESS;
}

