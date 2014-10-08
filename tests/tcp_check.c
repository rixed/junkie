// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#undef NDEBUG
#include <assert.h>
#include <time.h>
#include <junkie/cpp.h>
#include <junkie/tools/ext.h>
#include <junkie/tools/objalloc.h>
#include <junkie/proto/cap.h>
#include <junkie/proto/eth.h>
#include <junkie/proto/proto.h>
#include <junkie/proto/ip.h>
#include "lib_test_junkie.h"
#include "proto/pkt_wait_list.c"
#include "proto/tcp.c"

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

static struct parse_test_pkt {
    size_t size;
    uint8_t const packet[100];
    struct tcp_proto_info expected;
} parse_test_pkts [] = {
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
            0x00U, 0x50U, 0x9fU, 0x3fU, 0x37U, 0x88U, 0xcbU, 0x91U, 0xe2U, 0x3cU, 0x7aU, 0xbeU, 0x80U, 0x11U, 0x00U, 0x5bU,
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

static unsigned current_pkt;
static void tcp_info_check(struct proto_subscriber unused_ *s, struct proto_info const *info_, size_t unused_ cap_len, uint8_t const unused_ *packet, struct timeval const unused_ *now)
{
    // Check info against parse_test_pkts[current_pkt].expected
    struct tcp_proto_info const *const info = DOWNCAST(info_, info, tcp_proto_info);
    struct tcp_proto_info const *const expected = &parse_test_pkts[current_pkt].expected;
    assert(info->info.head_len == expected->info.head_len);
    assert(info->info.payload == expected->info.payload);
    assert(info->key.port[0] == expected->key.port[0]);
    assert(info->key.port[1] == expected->key.port[1]);
}

/*
 * Just check parse of tcp fields
 */
static void parse_check(void)
{
    struct timeval now;
    timeval_set_now(&now);
    struct parser *tcp_parser = proto_tcp->ops->parser_new(proto_tcp);
    assert(tcp_parser);
    struct proto_subscriber sub;
    hook_subscriber_ctor(&pkt_hook, &sub, tcp_info_check);

    for (current_pkt = 0; current_pkt < NB_ELEMS(parse_test_pkts); current_pkt++) {
        size_t const len = parse_test_pkts[current_pkt].size;
        int ret = tcp_parse(tcp_parser, NULL, current_pkt, parse_test_pkts[current_pkt].packet, len, len, &now, len, parse_test_pkts[current_pkt].packet);
        assert(0 == ret);
    }

    hook_subscriber_dtor(&pkt_hook, &sub);
    assert(tcp_parser->ref.count == 1);
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
        0xf6, 0xaa, 0x01, 0xbd, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x20, 0x80, 0x18, 0x2e, 0x96,
        0xf0, 0x7c, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x61, 0xdc, 0x20, 0x48, 0x00, 0x2c, 0x59, 0x8e }, };

static struct packet pkt_s2c_1 = {
    .way = FROM_SERVER,
    .packet = {
//                              SEQ                     ACK
        0x01, 0xbd, 0xf6, 0xaa, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x30, 0x80, 0x18, 0x2e, 0x96,
        0xf0, 0x7c, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x61, 0xdc, 0x20, 0x48, 0x00, 0x2c, 0x59, 0x8e } };

static struct packet pkt_c2s_2 = {
    .way = FROM_CLIENT,
    .packet = {
//                              SEQ                     ACK
        0xf6, 0xaa, 0x01, 0xbd, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x40, 0x80, 0x18, 0x2e, 0x96,
        0xf0, 0x7c, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x61, 0xdc, 0x20, 0x48, 0x00, 0x2c, 0x59, 0x8e }, };

static struct packet pkt_s2c_2 = {
    .way = FROM_SERVER,
    .packet = {
//                              SEQ                     ACK
        0x01, 0xbd, 0xf6, 0xaa, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x50, 0x80, 0x18, 0x2e, 0x96,
        0xf0, 0x7c, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x61, 0xdc, 0x20, 0x48, 0x00, 0x2c, 0x59, 0x8e } };

static struct packet pkt_c2s_3 = {
    .way = FROM_CLIENT,
    .packet = {
//                              SEQ                     ACK
        0xf6, 0xaa, 0x01, 0xbd, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x60, 0x80, 0x18, 0x2e, 0x96,
        0xf0, 0x7c, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x61, 0xdc, 0x20, 0x48, 0x00, 0x2c, 0x59, 0x8e }, };

static uint32_t *expected_wl_seqs;

static void pkt_wl_callback(struct proto_subscriber unused_ *s,
        struct proto_info const *info_, size_t unused_ cap_len,
        uint8_t const unused_ *packet, struct timeval const unused_ *now)
{
    if (cap_len == 0) return; // gap
    struct tcp_proto_info const *const info = DOWNCAST(info_, info, tcp_proto_info);
    SLOG(LOG_DEBUG, "Cb: %d, Got %"PRIu32", expected %"PRIu32, cb_called, info->seq_num,
            expected_wl_seqs[cb_called]);
    assert(info->seq_num == expected_wl_seqs[cb_called++]);
}

static void check_pkt(struct packet *pkts, unsigned nb_pkts, uint32_t *expected, unsigned nb_expected)
{
    SLOG(LOG_DEBUG, "-------Check packet---------------");
    struct timeval now;
    timeval_set_now(&now);
    struct parser *tcp_parser = proto_tcp->ops->parser_new(proto_tcp);
    assert(tcp_parser);
    struct proto_subscriber sub;
    hook_subscriber_ctor(&pkt_hook, &sub, pkt_wl_callback);
    cb_called = 0;
    expected_wl_seqs = expected;
    unsigned i = 0;
    for (i = 0; i < nb_pkts; i++) {
        int ret = tcp_parse(tcp_parser, NULL, pkts[i].way,
                    pkts[i].packet, test_cap_len, test_wire_len,
                    &now, test_cap_len, pkts[i].packet);
        assert(0 == ret);
    }
    for (unsigned l = 0; l < NB_ELEMS(tcp_wl_config.lists); l++) {
        for (unsigned i = 0; i < NB_ELEMS(tcp_wl_config.lists[l].list); i++) {
            struct pkt_wait_list *pkt_wl;
            LIST_FOREACH(pkt_wl, &tcp_wl_config.lists[l].list[i], entry) {
                pkt_wait_list_empty(pkt_wl);
            }
        }
    }

    SLOG(LOG_DEBUG, "Expected %d called, got %d", i, cb_called);
    assert(cb_called == nb_expected);
    hook_subscriber_dtor(&pkt_hook, &sub);
    assert(tcp_parser->ref.count == 1);
    parser_unref(&tcp_parser);
}

static enum proto_parse_status parse_err_parse(struct parser unused_ *parser, struct proto_info *parent,
        unsigned way, uint8_t const unused_ *packet, size_t cap_len, size_t wire_len,
        struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    if (cb_called < 2) {
        return proto_parse(NULL, parent,
                way, NULL,
                cap_len, wire_len,
                now, tot_cap_len, tot_packet);
    }
    return PROTO_PARSE_ERR;
}

static void pkt_wl_check(void)
{
    struct packet previous_ack_packets[3] = { pkt_s2c_1, pkt_c2s_1, pkt_c2s_2 };
    static uint32_t previous_ack_expected_seqs[3] = {0x20, 0x10, 0x30};
    check_pkt(previous_ack_packets, NB_ELEMS(previous_ack_packets),
            previous_ack_expected_seqs, NB_ELEMS(previous_ack_expected_seqs));

    static uint32_t reorder_expected_seqs[5] = {0x10, 0x20, 0x30, 0x40, 0x50};
    expected_wl_seqs = previous_ack_expected_seqs;
    struct packet reorder_packets[5] = { pkt_c2s_1, pkt_s2c_1, pkt_c2s_3, pkt_s2c_2, pkt_c2s_2 };
    check_pkt(reorder_packets, NB_ELEMS(reorder_packets),
            reorder_expected_seqs, NB_ELEMS(reorder_expected_seqs));

    // Force timeout of wl
    tcp_wl_config.nb_pkts_max = 1;

    // Callback should be called for every packets on timeout
    struct packet timeout_packets[5] = { pkt_c2s_1, pkt_s2c_1, pkt_c2s_3, pkt_s2c_2, pkt_c2s_2 };
    static uint32_t timeout_expected_seqs[5] = {0x10, 0x20, 0x40, 0x50, 0x30};
    check_pkt(timeout_packets, NB_ELEMS(timeout_packets),
            timeout_expected_seqs, NB_ELEMS(timeout_expected_seqs));

    static struct proto_ops const ops = {
        .parse      = parse_err_parse,
        .parser_new = uniq_parser_new,
        .parser_del = uniq_parser_del,
        .info_2_str = proto_info_2_str,
    };
    static struct uniq_proto uniq_proto_parse_err;
    static struct port_muxer tcp_port_muxer;
    uniq_proto_ctor(&uniq_proto_parse_err, &ops, "ParseErr", 42);
    port_muxer_ctor(&tcp_port_muxer, &tcp_port_muxers, 445, 445, &uniq_proto_parse_err.proto);

    // Callback should be called parse error inside timeouted packets
    struct packet parse_err_packets[5] = { pkt_c2s_1, pkt_s2c_1, pkt_c2s_3, pkt_s2c_2, pkt_c2s_2 };
    static uint32_t parse_err_expected_seqs[5] = {0x10, 0x20, 0x50, 0x30, 0x40};
    check_pkt(parse_err_packets, NB_ELEMS(parse_err_packets),
            parse_err_expected_seqs, NB_ELEMS(parse_err_expected_seqs));

    tcp_wl_config.nb_pkts_max = 20;
    struct packet reorder_after_err_packet[5] = { pkt_c2s_1, pkt_s2c_1, pkt_c2s_2, pkt_c2s_3, pkt_s2c_2 };
    static uint32_t parse_err_pkt_reorder[5] = {0x10, 0x20, 0x30, 0x40, 0x50};
    check_pkt(reorder_after_err_packet, NB_ELEMS(reorder_after_err_packet),
            parse_err_pkt_reorder, NB_ELEMS(parse_err_pkt_reorder));

    port_muxer_dtor(&tcp_port_muxer, &tcp_port_muxers);
    struct parser *parser = uniq_proto_parse_err.parser;
    uniq_proto_dtor(&uniq_proto_parse_err);
    assert(parser->ref.count == 0);
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
    log_set_level(LOG_WARNING, "mutex");
    log_set_level(LOG_WARNING, "redim_array");
    log_set_file("tcp_check.log");

    seqnum_test();
    parse_check();
    pkt_wl_check();

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

