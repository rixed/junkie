// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#undef NDEBUG
#include <assert.h>
#include <time.h>
#include <junkie/cpp.h>
#include <junkie/tools/ext.h>
#include <junkie/tools/objalloc.h>
#include <junkie/proto/ip.h>
#include "lib.h"
#include "proto/rtcp.c"

/*
 * Parse check
 */

static struct parse_test {
    uint8_t const packet[200];
    size_t size;
    struct expected {
        int32_t cumul_lost;
        uint32_t jitter;
        uint32_t lsr;
        uint32_t dlsr;
        uint32_t ntp_ts;
    } exp;
} parse_tests[] = {
    {
        .packet = { 0x0 },
        .size = 1,
        .exp = {
            .cumul_lost = 0,
            .jitter = 0,
            .lsr = 0,
            .dlsr = 0,
            .ntp_ts = 0,
        },
    }, {
        .packet = {
            0x81U, 0xC8U, 0x00U, 0x0CU, 0x95U, 0x89U, 0x7DU, 0x9EU,
            0xCCU, 0xE3U, 0x94U, 0xFCU, 0x32U, 0x65U, 0x9DU, 0x12U,
            0x22U, 0xC8U, 0x45U, 0x17U, 0x00U, 0x00U, 0x01U, 0xC9U,
            0x00U, 0x01U, 0xACU, 0x70U, 0x3CU, 0x42U, 0xA9U, 0xE7U,
            0x00U, 0x00U, 0x00U, 0x04U, 0x00U, 0x00U, 0x01U, 0xC9U,
            0x0EU, 0x4DU, 0x4CU, 0x80U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U
        },
        .size = 8 * 6 + 4,
        .exp = {
            .cumul_lost = 4,
            .jitter = 0x0E4D4C80,
            .lsr = 0,
            .dlsr = 0,
            .ntp_ts = 0x94FC3265,
        },
    }, {
        .packet = {
            0x80, 0xc9, 0x00, 0x01, 0x95, 0x89, 0x7d, 0x9e,
            0x81, 0xca, 0x00, 0x07, 0x95, 0x89, 0x7d, 0x9e,
            0x01, 0x13, 0x66, 0x72, 0x61, 0x6e, 0x63, 0x69,
            0x73, 0x40, 0x68, 0x61, 0x79, 0x64, 0x6e, 0x2e,
            0x64, 0x75, 0x72, 0x6f, 0x79, 0x00, 0x00, 0x00,
        },
        .size = 8 * 5,
        .exp = {
            .cumul_lost = 0,
            .jitter = 0,
            .lsr = 0,
            .dlsr = 0,
            .ntp_ts = 0,
        },
    },
};

static unsigned cur_test;

static void rtcp_info_check(struct proto_subscriber unused_ *s, struct proto_info const *info_, size_t unused_ cap_len, uint8_t const unused_ *packet, struct timeval const unused_ *now)
{
    struct rtcp_proto_info const *const info = DOWNCAST(info_, info, rtcp_proto_info);
    struct expected const *const exp = &parse_tests[cur_test].exp;

#define CHECK(field) assert(exp->field == info->field)

    CHECK(cumul_lost);
    CHECK(jitter);
    CHECK(lsr);
    CHECK(dlsr);
    CHECK(ntp_ts);

#undef CHECK
}

static void parse_check(void)
{
    struct timeval now;
    timeval_set_now(&now);
    struct parser *rtcp_parser = proto_rtcp->ops->parser_new(proto_rtcp);
    assert(rtcp_parser);
    struct proto_subscriber sub;
    hook_subscriber_ctor(&pkt_hook, &sub, rtcp_info_check);

    for (cur_test = 0; cur_test < NB_ELEMS(parse_tests); cur_test++) {
        (void)rtcp_parse(rtcp_parser, NULL, 0, parse_tests[cur_test].packet, parse_tests[cur_test].size, parse_tests[cur_test].size, &now, parse_tests[cur_test].size, parse_tests[cur_test].packet);
    }

    hook_subscriber_dtor(&pkt_hook, &sub);
    parser_unref(&rtcp_parser);
}

struct proto *proto_ip;
struct proto *proto_dns;
struct proto *proto_sip;
struct proto *proto_udp;

int main(void)
{
    log_init();
    ext_init();
    objalloc_init();
    ref_init();
    proto_init();
    rtcp_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("rtcp_check.log");

    proto_ip = proto_dummy;
    proto_dns  = proto_dummy;
    proto_sip = proto_dummy;
    proto_udp = proto_dummy;

    parse_check();
    stress_check(proto_rtcp);

    doomer_stop();
    rtcp_fini();
    proto_fini();
    ref_fini();
    objalloc_fini();
    ext_fini();
    log_fini();
    return EXIT_SUCCESS;
}
