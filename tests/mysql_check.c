// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#undef NDEBUG
#include <assert.h>
#include <time.h>
#include <junkie/cpp.h>
#include <junkie/tools/ext.h>
#include <junkie/tools/objalloc.h>
#include <junkie/proto/cursor.h>
#include <junkie/proto/tcp.h>
#include <junkie/proto/ip.h>
#include <junkie/proto/eth.h>
#include <junkie/proto/pkt_wait_list.h>
#include "lib.h"
#include "proto/mysql.c"
#include "sql_test.h"


static struct parse_test {
    uint8_t const *packet;
    int size;
    enum proto_parse_status ret;         // Expected proto status
    struct sql_proto_info expected;
    enum way way;
} parse_tests[] = {

    // Server greetings
    {
        .packet = (uint8_t const []) {
            0x56, 0x00, 0x00, 0x00, 0x0a, 0x35, 0x2e, 0x35, 0x2e, 0x33, 0x32, 0x2d,
            0x4d, 0x61, 0x72, 0x69, 0x61, 0x44, 0x42, 0x2d, 0x6c, 0x6f, 0x67, 0x00,
            0x2e, 0x05, 0x01, 0x00, 0x3f, 0x27, 0x43, 0x5e, 0x2e, 0x6a, 0x4c, 0x7b,
            0x00, 0xff, 0xf7, 0x21, 0x02, 0x00, 0x0f, 0xa0, 0x15, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x3f, 0x3c, 0x50, 0x5e,
            0x66, 0x68, 0x55, 0x52, 0x79, 0x2f, 0x77, 0x00, 0x6d, 0x79, 0x73, 0x71,
            0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x70, 0x61, 0x73,
            0x73, 0x77, 0x6f, 0x72, 0x64, 0x00
        },
        .size = 0x5a,
        .ret = PROTO_OK,
        .way = FROM_SERVER,
        .expected = {
            .info = { .head_len = 0x5a, .payload = 0},
            .set_values = SQL_VERSION,
            .msg_type = SQL_STARTUP,
            .version_maj = 10,
            .version_min = 0,
        },
    },

    // Login request
    {
        .packet = (uint8_t const []) {
            0x41, 0x00, 0x00, 0x01, 0x8d, 0xa2, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x66, 0x72, 0x65, 0x64, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74, 0x00, 0x6d,
            0x79, 0x73, 0x71, 0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x5f,
            0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00
        },
        .size = 0x45,
        .ret = PROTO_OK,
        .way = FROM_CLIENT,
        .expected = {
            .info = { .head_len = 0x45, .payload = 0},
            .set_values = SQL_DBNAME | SQL_USER | SQL_PASSWD | SQL_ENCODING,
            .msg_type = SQL_STARTUP,
            .u = { .startup = { .user = "cods", .dbname = "test", .passwd = "test", .encoding = SQL_ENCODING_UTF8 } },
        },
    },

};

static unsigned cur_test;

static void mysql_info_check(struct proto_subscriber unused_ *s, struct proto_info const *info_, size_t unused_ cap_len, uint8_t const unused_ *packet, struct timeval const unused_ *now)
{
    // Check info against parse_tests[cur_test].expected
    struct sql_proto_info const *const info = DOWNCAST(info_, info, sql_proto_info);
    struct sql_proto_info const *const expected = &parse_tests[cur_test].expected;
    assert(!compare_expected_sql(info, expected));
}

static void parse_check(void)
{
    struct timeval now;
    timeval_set_now(&now);
    struct parser *parser = proto_mysql->ops->parser_new(proto_mysql);
    struct mysql_parser *mysql_parser = DOWNCAST(parser, parser, mysql_parser);
    assert(mysql_parser);
    struct proto_subscriber sub;
    hook_subscriber_ctor(&pkt_hook, &sub, mysql_info_check);

    for (cur_test = 0; cur_test < NB_ELEMS(parse_tests); cur_test++) {
        struct parse_test const *test = parse_tests + cur_test;
        printf("Check packet %d of size 0x%x (%d)\n", cur_test, test->size, test->size);
        enum proto_parse_status ret = mysql_parse(parser, NULL, test->way, test->packet, test->size,
                test->size, &now, test->size, test->packet);
        assert(ret == test->ret);
    }
    hook_subscriber_dtor(&pkt_hook, &sub);
}

int main(void)
{
    log_init();
    ext_init();
    objalloc_init();
    ref_init();
    proto_init();
    port_muxer_init();
    pkt_wait_list_init();
    streambuf_init();
    eth_init();
    ip_init();
    ip6_init();
    tcp_init();
    mysql_init();
    tds_msg_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("mysql_check.log");

    parse_check();

    doomer_stop();
    tds_msg_fini();
    mysql_fini();
    tcp_fini();
    ip6_fini();
    ip_fini();
    eth_fini();
    streambuf_fini();
    pkt_wait_list_fini();
    port_muxer_fini();
    proto_fini();
    ref_fini();
    objalloc_fini();
    ext_fini();
    log_fini();
    return EXIT_SUCCESS;
}

