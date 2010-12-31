// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#include <assert.h>
#include <junkie/cpp.h>
#include "lib.h"
#include "proto/icmp.c"
#include "proto/icmpv6.c"

/*
 * Parse check
 */

static struct parse_test {
    unsigned version;
    size_t size;
    uint8_t const *packet;
    struct icmp_proto_info expected;
    char const *src, *dst;
} parse_tests [] = {
    {
        .version = 4,
        .size = 2*16 + 4,
        .packet = (uint8_t const []) {
            0x03, 0x01, 0xc4, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x45, 0x00, 0x05, 0xdc, 0x1e, 0xfc, 0x20, 0x00,
            0x40, 0x01, 0x57, 0x21, 0xc0, 0xa8, 0x0a, 0x04, 0xd8, 0xef, 0x3b, 0x68, 0x08, 0x00, 0x2d, 0x04,
            0x03, 0x59, 0x00, 0x01,
        },
        .expected = {
            .info = { .head_len = 2*16+4, .payload = 0, },
            .type = 3, .code = 1, .set_values = ICMP_ERR_SET,
            .err = { .protocol = 1, }
        },
        .src = "192.168.10.4", .dst = "216.239.59.104",
    }, {
        .version = 4,
        .size = 2*16 + 4,
        .packet = (uint8_t const []) {
            0x03, 0x03, 0x9e, 0x88, 0x00, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00, 0x1c, 0x79, 0xf1, 0x00, 0x00,
            0x40, 0x11, 0x5f, 0x6e, 0xc0, 0xa8, 0x0a, 0x04, 0x58, 0xa1, 0x7e, 0x24, 0x08, 0x48, 0x0c, 0x3b,
            0x00, 0x08, 0x49, 0xe9,
        },
        .expected = {
            .info = { .head_len = 2*16+4, .payload = 0, },
            .type = 3, .code = 3, .set_values = ICMP_ERR_SET|ICMP_ERR_PORT_SET,
            .err = { .protocol = 17, .port = { 2120, 3131 } }
        },
        .src = "192.168.10.4", .dst = "88.161.126.36",
    }, {
        .version = 4,
        .size = 4*16,
        .packet = (uint8_t const []) {
            0x08, 0x00, 0x6a, 0x34, 0x8c, 0x13, 0x00, 0x01, 0x69, 0x0e, 0x35, 0x49, 0x72, 0x5c, 0x06, 0x00,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        },
        .expected = {
            .info = { .head_len = 4*16, .payload = 0, },
            .type = 8, .code = 0, .set_values = 0,
        },
    }, {
        .version = 4,
        .size = 2*16+4,
        .packet = (uint8_t const []) {
            0x0b, 0x00, 0xf6, 0xb6, 0x00, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
            0x01, 0x01, 0xd8, 0x37, 0xc0, 0xa8, 0x0a, 0x04, 0x58, 0xa1, 0x7e, 0x24, 0x08, 0x00, 0x6a, 0x34,
            0x8c, 0x13, 0x00, 0x01,
        },
        .expected = {
            .info = { .head_len = 2*16+4, .payload = 0, },
            .type = 11, .code = 0, .set_values = ICMP_ERR_SET,
            .err = { .protocol = 1, }
        },
        .src = "192.168.10.4", .dst = "88.161.126.36",
    }, {
        .version = 6,
        .size = 16*4,
        .packet = (uint8_t const []) {
            0x81, 0x00, 0xf0, 0xb2, 0x7e, 0x15, 0x00, 0x02, 0x3c, 0x3e, 0xed, 0x4b, 0x00, 0x00, 0x00, 0x00,
            0x22, 0x5c, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        },
        .expected = {
            .info = { .head_len = 16*4, .payload = 0, },
            .type = 129, .code = 0, .set_values = 0,
        },
    }
};

static unsigned current_test;

static int icmp_info_check(struct proto_info const *info_)
{
    struct icmp_proto_info const *const info = DOWNCAST(info_, info, icmp_proto_info);
    struct icmp_proto_info const *const expected = &parse_tests[current_test].expected;
    assert(info->info.head_len == expected->info.head_len);
    assert(info->info.payload == expected->info.payload);
    assert(info->type == expected->type);
    assert(info->code == expected->code);
    assert(info->set_values == expected->set_values);
    if (info->set_values & ICMP_ERR_SET) {
        struct parse_test const *const test = parse_tests + current_test;
        struct ip_addr src, dst;
        assert(0 == ip_addr_ctor_from_str(&src, test->src, strlen(test->src), 4));
        assert(0 == ip_addr_ctor_from_str(&dst, test->dst, strlen(test->dst), 4));
        assert(info->err.protocol == expected->err.protocol);
        assert(0 == ip_addr_cmp(info->err.addr+0, &src));
        assert(0 == ip_addr_cmp(info->err.addr+1, &dst));
        if (info->set_values & ICMP_ERR_PORT_SET) {
            assert(info->err.port[0] == expected->err.port[0]);
            assert(info->err.port[1] == expected->err.port[1]);
        }
    }
    return 0;
}

static void parse_check(void)
{
    struct timeval now;
    timeval_set_now(&now);
    struct parser *icmp_parser = proto_icmp->ops->parser_new(proto_icmp, &now);
    assert(icmp_parser);
    struct parser *icmpv6_parser = proto_icmpv6->ops->parser_new(proto_icmpv6, &now);
    assert(icmpv6_parser);

    for (current_test = 0; current_test < NB_ELEMS(parse_tests); current_test++) {
        struct parse_test const *const test = parse_tests + current_test;
        printf("Test packet %u... ", current_test);
        int ret = test->version == 4 ?
            icmp_parse(icmp_parser, NULL, 0, test->packet, test->size, test->size, &now, icmp_info_check) :
            icmpv6_parse(icmpv6_parser, NULL, 0, test->packet, test->size, test->size, &now, icmp_info_check);
        assert(0 == ret);
        printf("Ok\n");
    }

    parser_unref(icmpv6_parser);
    parser_unref(icmp_parser);
}

int main(void)
{
    log_init();
    icmp_init();
    icmpv6_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("icmp_check.log");

    parse_check();
    stress_check(proto_icmp);
    stress_check(proto_icmpv6);

    icmpv6_fini();
    icmp_fini();
    log_fini();
    return EXIT_SUCCESS;
}

