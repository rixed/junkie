// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#undef NDEBUG
#include <assert.h>
#include <time.h>
#include <junkie/cpp.h>
#include <junkie/tools/ext.h>
#include <junkie/tools/mutex.h>
#include <junkie/proto/pkt_wait_list.h>
#include <junkie/proto/cap.h>
#include <junkie/proto/eth.h>
#include <junkie/proto/ip.h>
#include <junkie/proto/udp.h>
#include <junkie/proto/tcp.h>
#include <junkie/proto/cnxtrack.h>
#include "lib.h"
#include "proto/sip.c"

/*
 * Parse check
 */

static struct parse_test {
    uint8_t const *packet;
    struct sip_proto_info expected;
    enum proto_parse_status ret;    // expected return code
} parse_tests[] = {
    {
        .packet = (uint8_t const *)
        "INVITE sip:0671396213@freephonie.net SIP/2.0\r\n"
        "Call-ID: kegbwtzfciwlmnf@192.168.129.14\r\n"
        "From: <bar@sip.org> Mrs Bar\r\n"
        "To: <foo@sip.org> Mr Foo\r\n"
        "CSeq: 632 INVITE\r\n"
        "Via: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK276f53f4\r\n"
        "Content-Length: 100\r\n"
        "Content-Type: application/sdp\r\n"
        "\r\n"
        "XXX",
        .expected = {
            .info = { .head_len = 268, .payload = 3 },
            .set_values = SIP_CMD_SET | SIP_CSEQ_SET | SIP_CALLID_SET | SIP_FROM_SET | SIP_TO_SET | SIP_LENGTH_SET | SIP_MIME_SET | SIP_VIA_SET,
            .cmd = SIP_CMD_INVITE,
            .call_id = "kegbwtzfciwlmnf@192.168.129.14",
            .from = "<bar@sip.org> Mrs Bar",
            .to = "<foo@sip.org> Mr Foo",
            .content_length = 100,
            .mime_type = "application/sdp",
            .via = { .protocol = 17, .addr = { .family = AF_INET, .u.v4.s_addr = 0x04030201, }, .port = 5060 },
            .cseq = 632,
            .code = 0,
        },
        .ret = PROTO_OK,
    },
    {
        .packet = (uint8_t const *)
        "SIP/2.0 200 OK\r\n"
        "From: <bar@sip.org>\r\n"
        "To: <foo@sip.org>\r\n"
        "CSeq: 632 INVITE\r\n"
        "Content-Length: 100\r\n"
        "Content-Type: application/sdp\r\n"
        "\r\n",
        .expected = {
            .info = { .head_len = 128, .payload = 0 },
            .set_values = SIP_CODE_SET | SIP_CSEQ_SET | SIP_FROM_SET | SIP_TO_SET | SIP_LENGTH_SET | SIP_MIME_SET,
            .from = "<bar@sip.org>",
            .to = "<foo@sip.org>",
            .content_length = 100,
            .mime_type = "application/sdp",
            .cseq = 632,
            .code = 200,
        },
        .ret = PROTO_OK,
    },
    {
        .packet = (uint8_t const *)
        "SIP/3.0 4242 FOO\r\n" // unrecognized version
        "\r\n",
        .expected = {
            .info = { .head_len = 20, .payload = 0 },
            .set_values = 0,
            .from = "",
            .to = "",
            .content_length = 0,
            .mime_type = "",
            .cseq = 0,
            .code = 0,
        },
        .ret = PROTO_PARSE_ERR,
    }
};

static unsigned cur_test;

static int sip_info_check(struct proto_info const *info_, size_t unused_ cap_len, uint8_t const unused_ *packet)
{
    // Check info against parse_tests[cur_test].expected
    struct sip_proto_info const *const info = DOWNCAST(info_, info, sip_proto_info);
    struct sip_proto_info const *const expected = &parse_tests[cur_test].expected;

    assert(info->info.head_len == expected->info.head_len);
    assert(info->info.payload  == expected->info.payload);
    assert(info->set_values    == expected->set_values);
    if (info->set_values & SIP_CSEQ_SET)   assert(info->cseq           == expected->cseq);
    if (info->set_values & SIP_LENGTH_SET) assert(info->content_length == expected->content_length);
    if (info->set_values & SIP_CODE_SET)   assert(info->code           == expected->code);
    if (info->set_values & SIP_CMD_SET)    assert(info->cmd            == expected->cmd);
    if (info->set_values & SIP_FROM_SET)   assert(0 == memcmp(info->from,      expected->from,      strlen(expected->from)));
    if (info->set_values & SIP_TO_SET)     assert(0 == memcmp(info->to,        expected->to,        strlen(expected->to)));
    if (info->set_values & SIP_MIME_SET)   assert(0 == memcmp(info->mime_type, expected->mime_type, strlen(expected->mime_type)));
    if (info->set_values & SIP_VIA_SET) {
        assert(info->via.protocol == expected->via.protocol);
        assert(0 == ip_addr_cmp(&info->via.addr, &expected->via.addr));
        assert(info->via.port == expected->via.port);
    }

    return 0;
}

static void parse_check(void)
{
    struct timeval now;
    timeval_set_now(&now);
    struct parser *sip_parser = proto_sip->ops->parser_new(proto_sip);
    assert(sip_parser);

    for (cur_test = 0; cur_test < NB_ELEMS(parse_tests); cur_test++) {
        size_t const len = strlen((char *)parse_tests[cur_test].packet);
        enum proto_parse_status ret = sip_parse(sip_parser, NULL, 0, parse_tests[cur_test].packet, len, len, &now, sip_info_check, len, parse_tests[cur_test].packet);
        assert(ret == parse_tests[cur_test].ret);
    }

    parser_unref(sip_parser);
}

struct proto *proto_sdp;

int main(void)
{
    log_init();
    mutex_init();
    ext_init();
    mallocer_init();
    hash_init();
    proto_init();
    cnxtrack_init();
    pkt_wait_list_init();
    ref_init();
    cap_init();
    eth_init();
    ip_init();
    ip6_init();
    udp_init();
    tcp_init();
    sip_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("sip_check.log");

    proto_sdp = proto_dummy;

    parse_check();
    stress_check(proto_sip);

    doomer_stop();
    sip_fini();
    tcp_fini();
    udp_fini();
    ip6_fini();
    ip_fini();
    eth_fini();
    cap_fini();
    ref_fini();
    pkt_wait_list_fini();
    cnxtrack_fini();
    proto_fini();
    hash_fini();
    mallocer_fini();
    ext_fini();
    mutex_fini();
    log_fini();
    return EXIT_SUCCESS;
}

