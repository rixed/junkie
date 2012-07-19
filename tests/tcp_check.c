// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#undef NDEBUG
#include <assert.h>
#include <time.h>
#include <junkie/cpp.h>
#include <junkie/tools/ext.h>
#include <junkie/tools/objalloc.h>
#include <junkie/proto/pkt_wait_list.h>
#include <junkie/proto/cap.h>
#include <junkie/proto/eth.h>
#include <junkie/proto/ip.h>
#include "lib.h"
#include "proto/tcp.c"

/*
 * Some unit tests
 */

static void seqnum_test(void)
{
    struct sq_test {
        uint32_t a, b;
        bool gt;
    } const tests[] = {
        { 1, 0, true }, { 0xe0000000, 0xa0000000, true }, { 0x20000000, 0xf0000000, true },
        { 0, 0, false }, { 0xffffffff, 0x50000000, false },
    };

    for (unsigned t = 0; t < NB_ELEMS(tests); t ++) {
        struct sq_test const *test = tests + t;
        assert(seqnum_gt(test->a, test->b) == test->gt);
        assert(seqnum_gt(test->b, test->a) == (test->a == test->b ? false : !test->gt));
    }
}

/*
 * Parse check
 */

static struct parse_test {
    size_t size;
    uint8_t const packet[100];
    struct tcp_proto_info expected;
} parse_tests [] = {
    {
        .size = 16*2+8, .packet = {
            0x9fU, 0x3fU, 0x00U, 0x50U, 0xe2U, 0x3cU, 0x7aU, 0xbeU, 0x00U, 0x00U, 0x00U, 0x00U, 0xa0U, 0x02U, 0x16U, 0xd0U,
            0xf2U, 0x73U, 0x00U, 0x00U, 0x02U, 0x04U, 0x05U, 0xb4U, 0x04U, 0x02U, 0x08U, 0x0aU, 0x1dU, 0xd6U, 0x82U, 0xeaU,
            0x00U, 0x00U, 0x00U, 0x00U, 0x01U, 0x03U, 0x03U, 0x06U,
        }, .expected = {
            .info = { .head_len = 40, .payload = 0 },
            .key = { .port = { 40767, 80 } },
            .syn = 1, .ack = 0, .rst = 0, .fin = 0,
            .window = 5840,
            .ack_num = 0, .seq_num = 3795614398,
        },
    }, {
        .size = 16*2, .packet = {
            0x00U, 0x50U, 0x9fU, 0x3fU, 0x37U, 0x88U, 0xcbU, 0x91U, 0xe2U, 0x3cU, 0x7aU, 0xd2U, 0x80U, 0x11U, 0x00U, 0x5bU,
            0xdaU, 0xe1U, 0x00U, 0x00U, 0x01U, 0x01U, 0x08U, 0x0aU, 0x46U, 0xb3U, 0x08U, 0xb8U, 0x1dU, 0xd6U, 0x8dU, 0x13U,
        }, .expected = {
            .info = { .head_len = 32, .payload = 0 },
            .key = { .port = { 80, 40767 } },
            .syn = 0, .ack = 1, .rst = 0, .fin = 1,
            .window = 91,
            .ack_num = 3795614418, .seq_num = 931711889,
        },
    }
};

static unsigned current_test;

static void tcp_info_check(struct proto_subscriber unused_ *s, struct proto_info const *info_, size_t unused_ cap_len, uint8_t const unused_ *packet, struct timeval const unused_ *now)
{
    // Check info against parse_tests[current_test].expected
    struct tcp_proto_info const *const info = DOWNCAST(info_, info, tcp_proto_info);
    struct tcp_proto_info const *const expected = &parse_tests[current_test].expected;
    assert(info->info.head_len == expected->info.head_len);
    assert(info->info.payload == expected->info.payload);
    assert(info->key.port[0] == expected->key.port[0]);
    assert(info->key.port[1] == expected->key.port[1]);
}

static void parse_check(void)
{
    struct timeval now;
    timeval_set_now(&now);
    struct parser *tcp_parser = proto_tcp->ops->parser_new(proto_tcp);
    assert(tcp_parser);
    struct proto_subscriber sub;
    proto_pkt_subscriber_ctor(&sub, tcp_info_check);

    for (current_test = 0; current_test < NB_ELEMS(parse_tests); current_test++) {
        size_t const len = parse_tests[current_test].size;
        int ret = tcp_parse(tcp_parser, NULL, 0, parse_tests[current_test].packet, len, len, &now, len, parse_tests[current_test].packet);
        assert(0 == ret);
    }

    proto_pkt_subscriber_dtor(&sub);
    parser_unref(tcp_parser);
}

/*
 * Termination check.
 * Make sure that we have 1 subparser until the stream is over, then 0
 */

static void term_check(void)
{
    struct timeval now;
    timeval_set_now(&now);
    struct tcp_stream stream;
    assert(0 == tcp_stream_ctor(&stream, 5000, 2000, 443));

    struct parser *tcp_parser = proto_tcp->ops->parser_new(proto_tcp);
    assert(tcp_parser);
    struct mux_parser *mux_parser = DOWNCAST(tcp_parser, parser, mux_parser);

    bool first = true;
    ssize_t sz;
    unsigned way;
    while (0 < (sz = tcp_stream_next(&stream, &way))) {
        // check we have 1 subparser (or 0 at first)
        assert(first || mux_parser->nb_children == 1);
        first = false;

        int ret = tcp_parser->proto->ops->parse(tcp_parser, NULL, way, stream.packet + 20 /* skip ip */, sz - 20, sz - 20, &now, sz, stream.packet);
        assert(0 == ret);
    }
    assert(sz == 0);

    assert(mux_parser->nb_children == 0);

    parser_unref(tcp_parser);

    tcp_stream_dtor(&stream);
}

int main(void)
{
    log_init();
    ext_init();
    objalloc_init();
    pkt_wait_list_init();
    ref_init();
    hash_init();
    ext_init();
    proto_init();
    cap_init();
    eth_init();
    ip_init();
    ip6_init();
    tcp_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("tcp_check.log");

    seqnum_test();
    term_check();
    parse_check();
    stress_check(proto_tcp);

    doomer_stop();
    tcp_fini();
    ip6_fini();
    ip_fini();
    eth_fini();
    cap_fini();
    proto_fini();
    hash_fini();
    ext_fini();
    ref_fini();
    pkt_wait_list_fini();
    objalloc_fini();
    ext_fini();
    log_fini();
    return EXIT_SUCCESS;
}

