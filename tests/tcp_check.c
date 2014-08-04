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
#include "lib_test_junkie.h"
#include "proto/tcp.c"
#include "proto/mysql.c"

static unsigned current_test;
static unsigned cb_called;

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
    hook_subscriber_ctor(&pkt_hook, &sub, tcp_info_check);

    for (current_test = 0; current_test < NB_ELEMS(parse_tests); current_test++) {
        size_t const len = parse_tests[current_test].size;
        int ret = tcp_parse(tcp_parser, NULL, 0, parse_tests[current_test].packet, len, len, &now, len, parse_tests[current_test].packet);
        assert(0 == ret);
    }

    hook_subscriber_dtor(&pkt_hook, &sub);
    parser_unref(&tcp_parser);
}

struct packet {
    unsigned way;
    uint8_t const packet[32];
};

static size_t const test_cap_len = 0x20;
static size_t const test_wire_len = 0x40;

static struct packet pkt_c2s_1 = {
    .way = FROM_CLIENT,
    .packet = {
//                              SEQ                     ACK
        0xf6, 0xaa, 0x01, 0xbd, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x80, 0x18, 0x2e, 0x96,
        0xf0, 0x7c, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x61, 0xdc, 0x20, 0x48, 0x00, 0x2c, 0x59, 0x8e }, };

static struct packet pkt_s2c_1 = {
    .way = FROM_SERVER,
    .packet = {
//                              SEQ                     ACK
        0x01, 0xbd, 0xf6, 0xaa, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x80, 0x18, 0x2e, 0x96,
        0xf0, 0x7c, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x61, 0xdc, 0x20, 0x48, 0x00, 0x2c, 0x59, 0x8e } };

static struct packet pkt_c2s_2 = {
    .way = FROM_CLIENT,
    .packet = {
//                              SEQ                     ACK
        0xf6, 0xaa, 0x01, 0xbd, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x20, 0x80, 0x18, 0x2e, 0x96,
        0xf0, 0x7c, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x61, 0xdc, 0x20, 0x48, 0x00, 0x2c, 0x59, 0x8e }, };

uint32_t previous_ack_expected_seqs[3] = {0x20, 0x10, 0x30};
static void previous_ack_check(struct proto_subscriber unused_ *s, struct proto_info const *info_, size_t unused_ cap_len, uint8_t const unused_ *packet, struct timeval const unused_ *now)
{
    struct tcp_proto_info const *const info = DOWNCAST(info_, info, tcp_proto_info);
    cb_called++;
    assert(info->seq_num == previous_ack_expected_seqs[current_test]);
    return;
}

static void parse_with_previous_ack(void)
{
    struct packet previous_ack_packets[3] = { pkt_s2c_1, pkt_c2s_1, pkt_c2s_2 };
    struct timeval now;
    timeval_set_now(&now);
    struct parser *tcp_parser = proto_tcp->ops->parser_new(proto_tcp);
    assert(tcp_parser);
    struct proto_subscriber sub;
    hook_subscriber_ctor(&pkt_hook, &sub, previous_ack_check);
    cb_called = 0;
    for (current_test = 0; current_test < NB_ELEMS(previous_ack_packets); current_test++) {
        int ret = tcp_parse(tcp_parser, NULL, previous_ack_packets[current_test].way,
                previous_ack_packets[current_test].packet,
                test_cap_len, test_wire_len, &now, test_cap_len, previous_ack_packets[current_test].packet);
        assert(0 == ret);
        assert(cb_called == current_test + 1);
    }
    hook_subscriber_dtor(&pkt_hook, &sub);
    parser_unref(&tcp_parser);
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
    streambuf_init();
    proto_init();
    cap_init();
    eth_init();
    ip_init();
    ip6_init();
    tcp_init();
    mysql_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_level(LOG_WARNING, "mutex");
    log_set_file("tcp_check.log");

    seqnum_test();
    parse_check();
    parse_with_previous_ack();
    stress_check(proto_tcp);

    doomer_stop();
    mysql_fini();
    tcp_fini();
    ip6_fini();
    ip_fini();
    eth_fini();
    cap_fini();
    proto_fini();
    streambuf_fini();
    hash_fini();
    ext_fini();
    ref_fini();
    pkt_wait_list_fini();
    objalloc_fini();
    ext_fini();
    log_fini();
    return EXIT_SUCCESS;
}

