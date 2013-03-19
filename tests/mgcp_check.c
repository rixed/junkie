// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#undef NDEBUG
#include <assert.h>
#include <time.h>
#include <junkie/cpp.h>
#include <junkie/tools/objalloc.h>
#include <junkie/tools/ext.h>
#include <junkie/proto/pkt_wait_list.h>
#include <junkie/proto/cap.h>
#include <junkie/proto/eth.h>
#include <junkie/proto/ip.h>
#include <junkie/proto/udp.h>
#include "lib.h"
#include "proto/mgcp.c"

/*
 * Parse check
 */

static struct parse_test {
    uint8_t const *packet;
    struct mgcp_proto_info expected[4];
    int ret;    // expected return code
} parse_tests[] = {
    {
        .packet = (uint8_t const *)
        "NTFY 64440 aaln/1@[172.25.51.149] MGCP 1.0 NCS 1.0\r\n"
        "N: mgcp_tpip1@[82.101.41.7]:2427\r\n"
        "X: 3d00e\r\n"
        "O: l/hd\r\n",
        .expected[0] = {
            .info = { .head_len = 105, .payload = 0 },
            .response = false,
            .u.query = {
                .command = MGCP_Notify,
                .txid = 64440,
                .endpoint = "aaln/1@[172.25.51.149]",
            },
            .observed = MGCP_HD, .signaled = 0,
            .dialed = "", .cnx_id = "", .call_id = "",
        },
        .ret = 0,
    }, {
        .packet = (uint8_t const *)
        "200 64440 OK\n"
        ".\n"
        "RQNT 230621083 aaln/1@[172.25.51.149] MGCP 1.0 NCS 1.0\n"
        "K: 230614237\n"
        "X: 3d33000\n"
        "R: L/hf, L/hu\n",
        .expected = {
            {
                .info = { .head_len = 15, .payload = 0 },
                .response = true,
                .u.resp = {
                    .code = 200,
                    .txid = 64440,
                },
                .observed = 0, .signaled = 0,
                .dialed = "", .cnx_id = "", .call_id = "",
            }, {
                .info = { .head_len = 93, .payload = 0 },
                .response = false,
                .u.query = {
                    .command = MGCP_NotificationRequest,
                    .txid = 230621083,
                    .endpoint = "aaln/1@[172.25.51.149]",
                },
                .observed = 0, .signaled = 0,
                .dialed = "", .cnx_id = "", .call_id = "",
            },
        },
        .ret = 0,
    }, {
        .packet = (uint8_t const *)
        "NTFY 64441 aaln/1@[172.25.51.149] MGCP 1.0 NCS 1.0\n"
        "X: 3d33000\n"
        "O: d/0,d/6,d/T,d/4,d/3,d/1,d/2,d/8,d/7,d/1,d/2\n",
        .expected[0] = {
            .info = { .head_len = 109, .payload = 0 },
            .response = false,
            .u.query = {
                .command = MGCP_Notify,
                .txid = 64441,
                .endpoint = "aaln/1@[172.25.51.149]",
            },
            .observed = 0, .signaled = 0,
            .dialed = "0643128712", .cnx_id = "", .call_id = "",
        },
        .ret = 0,
    }
};

static unsigned cur_test, cur_msg;

static void mgcp_info_check(struct proto_subscriber unused_ *s, struct proto_info const *info_, size_t unused_ cap_len, uint8_t const unused_ *packet, struct timeval const unused_ *now)
{
    // Check info against parse_tests[cur_test].expected
    struct mgcp_proto_info const *const info = DOWNCAST(info_, info, mgcp_proto_info);
    struct mgcp_proto_info const *const expected = parse_tests[cur_test].expected + cur_msg;

    assert(info->info.head_len == expected->info.head_len);
    assert(info->info.payload  == expected->info.payload);
    assert(info->response      == expected->response);
    if (info->response) {
        struct mgcp_resp const *const got = &info->u.resp;
        struct mgcp_resp const *const want = &expected->u.resp;
        assert(got->code == want->code);
        assert(got->txid == want->txid);
    } else {
        struct mgcp_query const *const got = &info->u.query;
        struct mgcp_query const *const want = &expected->u.query;
        assert(got->command == want->command);
        assert(got->txid == want->txid);
        assert(0 == strcmp(got->endpoint, want->endpoint));
    }
    assert(info->observed == expected->observed);
    assert(info->signaled == expected->signaled);
    assert(0 == strcmp(info->dialed,  expected->dialed));
    assert(0 == strcmp(info->cnx_id,  expected->cnx_id));
    assert(0 == strcmp(info->call_id, expected->call_id));

    cur_msg ++;
}

static void parse_check(void)
{
    struct timeval now;
    timeval_set_now(&now);
    struct parser *mgcp_parser = proto_mgcp->ops->parser_new(proto_mgcp);
    assert(mgcp_parser);
    struct proto_subscriber sub;
    hook_subscriber_ctor(&pkt_hook, &sub, mgcp_info_check);

    for (cur_test = 0; cur_test < NB_ELEMS(parse_tests); cur_test++) {
        cur_msg = 0;
        struct parse_test const *test = parse_tests+cur_test;
        size_t const len = strlen((char *)test->packet);
        int ret = mgcp_parse(mgcp_parser, NULL, 0, test->packet, len, len, &now, len, test->packet);
        assert(ret == test->ret);
    }

    hook_subscriber_dtor(&pkt_hook, &sub);
    parser_unref(&mgcp_parser);
}

struct proto *proto_sdp;

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
    udp_init();
    mgcp_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("mgcp_check.log");
    proto_sdp = proto_dummy;

    parse_check();
    stress_check(proto_mgcp);

    doomer_stop();
    mgcp_fini();
    udp_fini();
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

