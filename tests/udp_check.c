// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <junkie/cpp.h>
#include <junkie/tools/timeval.h>
#include <junkie/tools/mallocer.h>
#include "lib.h"
#include "proto/udp.c"

/*
 * Parse check
 */

static struct parse_test {
    size_t size;
    uint8_t const packet[100];
    struct udp_proto_info expected;
} parse_tests [] = {
    {
        .size = 16*2+4, .packet = {
            0x9fU, 0xe7U, 0x00U, 0x35U, 0x00U, 0x24U, 0x86U, 0x35U, 0x8cU, 0xcfU, 0x01U, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x07U, 0x6cU, 0x65U, 0x6dU, 0x6fU, 0x6eU, 0x64U, 0x65U, 0x02U, 0x66U, 0x72U, 0x00U,
            0x00U, 0x1cU, 0x00U, 0x01U,
        }, .expected = {
            .info = { .head_len = 8, .payload = 28 },
            .key = { .port = { 40935, 53 } },
        },
    },
};

static unsigned current_test;

static int udp_info_check(struct proto_info const *info_, size_t unused_ cap_len, uint8_t const unused_ *packet)
{
    // Check info against parse_tests[current_test].expected
    struct udp_proto_info const *const info = DOWNCAST(info_, info, udp_proto_info);
    struct udp_proto_info const *const expected = &parse_tests[current_test].expected;
    assert(info->info.head_len == expected->info.head_len);
    assert(info->info.payload == expected->info.payload);
    assert(info->key.port[0] == expected->key.port[0]);
    assert(info->key.port[1] == expected->key.port[1]);

    return 0;
}

static void parse_check(void)
{
    struct timeval now;
    timeval_set_now(&now);
    struct parser *udp_parser = proto_udp->ops->parser_new(proto_udp, &now);
    assert(udp_parser);

    for (current_test = 0; current_test < NB_ELEMS(parse_tests); current_test++) {
        int ret = udp_parse(udp_parser, NULL, 0, parse_tests[current_test].packet, parse_tests[current_test].size, parse_tests[current_test].size, &now, udp_info_check, parse_tests[current_test].size, parse_tests[current_test].packet);
        assert(0 == ret);
    }

    parser_unref(udp_parser);
}

int main(void)
{
    log_init();
    mallocer_init();
    udp_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("udp_check.log");

    parse_check();
    stress_check(proto_udp);

    udp_fini();
    mallocer_fini();
    log_fini();
    return EXIT_SUCCESS;
}

