// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#undef NDEBUG
#include <assert.h>
#include <junkie/cpp.h>
#include <junkie/tools/objalloc.h>
#include <junkie/tools/ext.h>
#include <junkie/proto/pkt_wait_list.h>
#include <junkie/proto/cap.h>
#include <junkie/proto/eth.h>
#include <junkie/proto/ip.h>
#include "lib.h"

/*
 * Parse check
 */

static struct parse_test {
    size_t size;
    uint8_t const packet[104];
    struct ip_proto_info expected;
} parse_tests [] = {
    {
        .size = 16*3+1, .packet = {
            0x45U, 0x00U, 0x00U, 0x31U, 0x00U, 0x00U, 0x40U, 0x00U, 0x01U, 0x11U, 0x77U, 0x3eU, 0xc0U, 0xa8U, 0x0aU, 0x06U,
            0xefU, 0xffU, 0x47U, 0xd0U, 0xb0U, 0x72U, 0xb0U, 0x72U, 0x00U, 0x1dU, 0x11U, 0xa9U, 0x43U, 0x6cU, 0x69U, 0x71U,
            0x75U, 0x65U, 0x01U, 0x03U, 0xccU, 0xfeU, 0x12U, 0x56U, 0x01U, 0xccU, 0xfeU, 0x12U, 0x56U, 0x4bU, 0x69U, 0xe1U,
            0xc8U,
        }, .expected = {
            .info = { .head_len = 20, .payload = 29 }, .version = 4, .ttl = 1,
            .key = {
                .protocol = 17,
                .addr = {
                    { .family = AF_INET, .u = { .v4 = { 0x060aa8c0U } } },
                    { .family = AF_INET, .u = { .v4 = { 0xd047ffefU } } },
                },
            },
        },
    }, {
        .size = 16*3+4, .packet = {
            0x45U, 0x10U, 0x00U, 0x34U, 0x07U, 0x71U, 0x40U, 0x00U, 0x40U, 0x06U, 0x53U, 0xf5U, 0xc0U, 0xa8U, 0x0aU, 0x09U,
            0x52U, 0x43U, 0xc2U, 0x59U, 0xd1U, 0x96U, 0x08U, 0xaeU, 0x29U, 0x1cU, 0x9eU, 0x07U, 0x64U, 0xfbU, 0x34U, 0xe0U,
            0x80U, 0x10U, 0x01U, 0xf5U, 0xb2U, 0x55U, 0x00U, 0x00U, 0x01U, 0x01U, 0x08U, 0x0aU, 0x0dU, 0x55U, 0x2dU, 0x1dU,
            0x2eU, 0xe9U, 0x3eU, 0x85U,
        }, .expected = {
            .info = { .head_len = 20, .payload = 32 }, .version = 4, .ttl = 64,
            .key = {
                .protocol = 6,
                .addr = {
                    { .family = AF_INET, .u = { .v4 = { 0x090aa8c0U } } },
                    { .family = AF_INET, .u = { .v4 = { 0x59c24352U } } },
                },
            },
        },
    }, {
        .size = 16*6+8, .packet = {
            0x60U, 0x00U, 0x00U, 0x00U, 0x00U, 0x40U, 0x3aU, 0x40U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x01U, 0x80U, 0x00U, 0x4aU, 0x19U, 0xbbU, 0x5dU, 0x00U, 0x01U,
            0xdeU, 0xb9U, 0x1cU, 0x4dU, 0x00U, 0x00U, 0x00U, 0x00U, 0xbbU, 0x31U, 0x05U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U, 0x18U, 0x19U, 0x1aU, 0x1bU, 0x1cU, 0x1dU, 0x1eU, 0x1fU,
            0x20U, 0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U, 0x28U, 0x29U, 0x2aU, 0x2bU, 0x2cU, 0x2dU, 0x2eU, 0x2fU,
            0x30U, 0x31U, 0x32U, 0x33U, 0x34U, 0x35U, 0x36U, 0x37U,
        }, .expected = {
            .info = { .head_len = 40, .payload = 64 }, .version = 6, .ttl = 64,
            .key = {
                .protocol = 0x3a,
                .addr = {
                    { .family = AF_INET6, .u = { .v6 = { .s6_addr = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, } } } },
                    { .family = AF_INET6, .u = { .v6 = { .s6_addr = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, } } } },
                },
            },
        },
    },
};

static unsigned current_test;

static void ip_info_check(struct proto_subscriber unused_ *s, struct proto_info const *info_, size_t unused_ cap_len, uint8_t const unused_ *paclet, struct timeval const unused_ *now)
{
    // Check info against parse_tests[current_test].expected
    struct ip_proto_info const *const info = DOWNCAST(info_, info, ip_proto_info);
    struct ip_proto_info const *const expected = &parse_tests[current_test].expected;
    assert(info->info.head_len == expected->info.head_len);
    assert(info->info.payload == expected->info.payload);
    assert(info->version == expected->version);
    assert(0 == ip_addr_cmp(info->key.addr+0, expected->key.addr+0));
    assert(0 == ip_addr_cmp(info->key.addr+1, expected->key.addr+1));
    assert(info->key.protocol == expected->key.protocol);
    assert(info->ttl == expected->ttl);
}

static void parse_check(size_t cap_len_, size_t padding)
{
    struct timeval now;
    timeval_set_now(&now);
    struct parser *ip_parser = proto_ip->ops->parser_new(proto_ip);
    assert(ip_parser);
    struct parser *ip6_parser = proto_ip6->ops->parser_new(proto_ip);
    assert(ip6_parser);
    struct proto_subscriber sub;
    hook_subscriber_ctor(&pkt_hook, &sub, ip_info_check);

    for (current_test = 0; current_test < NB_ELEMS(parse_tests); current_test++) {
        struct parse_test const *const test = parse_tests + current_test;
        size_t const len = test->size;
        size_t const cap_len = len < cap_len_ ? len : cap_len_;
        int ret =
            (test->expected.version == 4 ? ip_parse : ip6_parse)(ip_parser, NULL, 0, parse_tests[current_test].packet, cap_len, len+padding, &now, cap_len, parse_tests[current_test].packet);
        assert(0 == ret);
    }

    hook_subscriber_dtor(&pkt_hook, &sub);
    parser_unref(&ip6_parser);
    parser_unref(&ip_parser);
}

int main(void)
{
    log_init();
    mutex_init();
    ext_init();
    objalloc_init();
    pkt_wait_list_init();
    ref_init();
    proto_init();
    cap_init();
    eth_init();
    ip_init();
    ip6_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("ip_check.log");

    parse_check(65535, 0);
    parse_check(65535, 6);  // The same, with 6 additional bytes on wire (to mimick Ethernet padding)
    for (size_t cap_len = 40; cap_len < 50; cap_len++) {
        parse_check(cap_len, 0);
        parse_check(cap_len, 6);
    }
    stress_check(proto_ip);

    doomer_stop();
    ip6_fini();
    ip_fini();
    eth_fini();
    cap_fini();
    proto_fini();
    ref_fini();
    pkt_wait_list_fini();
    objalloc_fini();
    ext_fini();
    mutex_fini();
    log_fini();
    return EXIT_SUCCESS;
}

