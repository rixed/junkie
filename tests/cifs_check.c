// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#undef NDEBUG
#include <assert.h>
#include <junkie/cpp.h>
#include <junkie/tools/ext.h>
#include <junkie/tools/objalloc.h>
#include <junkie/proto/pkt_wait_list.h>
#include <junkie/proto/cap.h>
#include <junkie/proto/ip.h>
#include <junkie/proto/eth.h>
#include <junkie/proto/tcp.h>
#include "lib.h"
#include "proto/cifs.c"

static char const *set_value_2_str(unsigned value)
{
    switch (value) {
        case SMB_DOMAIN: return "SMB_DOMAIN";
        default: return tempstr_printf("Unknown value %d", value);
    }
}

static struct parse_test {
    uint8_t const *packet;
    int size;
    enum proto_parse_status ret;
    struct cifs_proto_info expected;
    bool way;
} parse_tests[] = {

    // a negociate response
    {
        .packet = (uint8_t const []) {
//          Header-{-               Nego
            0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x80, 0x03, 0xc0, 0x00, 0x00, 0x00, 0x00,
//                                                                                                      -}
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x47, 0x00, 0x00, 0x01, 0x00,
//          WC-
            0x11, 0x02, 0x00, 0x03, 0x32, 0x00, 0x01, 0x00, 0x04, 0x41, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
//                                  Capabilities----------
            0xcc, 0x77, 0x00, 0x00, 0xfd, 0xf3, 0x80, 0x00, 0x00, 0xb5, 0x65, 0x00, 0x86, 0x6f, 0xcf, 0x01,
//                      Chal  BC--------
            0x88, 0xff, 0x08, 0x1c, 0x00, 0xbc, 0x52, 0x94, 0xe1, 0x5d, 0xf2, 0x8f, 0x5f, 0x57, 0x00, 0x4f,
            0x00, 0x52, 0x00, 0x4b, 0x00, 0x47, 0x00, 0x52, 0x00, 0x4f, 0x00, 0x55, 0x00, 0x50, 0x00, 0x00,
            0x00
        },
        .size = 0x61,
        .ret = PROTO_OK,
        .way = FROM_SERVER,
        .expected = {
            .info = { .head_len = CIFS_HEADER_SIZE, .payload = 0x61 - CIFS_HEADER_SIZE},
            .command = SMB_COM_NEGOCIATE,
            .domain = "WORKGROUP",
            .set_values = SMB_DOMAIN,
        },
    },

    // session setup andx
    {
        .packet = (uint8_t const []) {
//          Header {
            0xff, 0x53, 0x4d, 0x42, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xd0, 0x00, 0x00, 0x00, 0x00,
//                                                                                                       }
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x47, 0x00, 0x00, 0x02, 0x00,
//          WC
            0x0d, 0xff, 0x00, 0x00, 0x00, 0x54, 0x40, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18,
//                                                                            ByteCount-  Oem{
            0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdc, 0xd0, 0x80, 0x00, 0xb1, 0x00, 0xd4, 0x91, 0x12,
            0xc6, 0x47, 0xc3, 0xc6, 0x2f, 0xf9, 0x4b, 0xb5, 0xad, 0xdb, 0x66, 0x63, 0xb0, 0x18, 0x7c, 0x87,
//                                     }  Unic{
            0x3a, 0x8e, 0x04, 0xef, 0x34, 0xd4, 0x91, 0x12, 0xc6, 0x47, 0xc3, 0xc6, 0x2f, 0xf9, 0x4b, 0xb5,
//                                                                                     }  Padd  User-{
            0xad, 0xdb, 0x66, 0x63, 0xb0, 0x18, 0x7c, 0x87, 0x3a, 0x8e, 0x04, 0xef, 0x34, 0x00,  'T', 0x00,
//                                                                                                      -}
            'o' , 0x00, 't' , 0x00, 'o' , 0x00, 't' , 0x00, 'e' , 0x00, 's' , 0x00, 't' , 0x00, 0x00, 0x00,
            0x00, 0x00, 0x4c, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x75, 0x00, 0x78, 0x00, 0x20, 0x00, 0x76, 0x00,
            0x65, 0x00, 0x72, 0x00, 0x73, 0x00, 0x69, 0x00, 0x6f, 0x00, 0x6e, 0x00, 0x20, 0x00, 0x33, 0x00,
            0x2e, 0x00, 0x32, 0x00, 0x2e, 0x00, 0x30, 0x00, 0x2d, 0x00, 0x34, 0x00, 0x2d, 0x00, 0x61, 0x00,
            0x6d, 0x00, 0x64, 0x00, 0x36, 0x00, 0x34, 0x00, 0x00, 0x00, 0x43, 0x00, 0x49, 0x00, 0x46, 0x00,
            0x53, 0x00, 0x20, 0x00, 0x56, 0x00, 0x46, 0x00, 0x53, 0x00, 0x20, 0x00, 0x43, 0x00, 0x6c, 0x00,
            0x69, 0x00, 0x65, 0x00, 0x6e, 0x00, 0x74, 0x00, 0x20, 0x00, 0x66, 0x00, 0x6f, 0x00, 0x72, 0x00,
            0x20, 0x00, 0x4c, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x75, 0x00, 0x78, 0x00, 0x00, 0x00
        },
        .size = 0xee,
        .ret = PROTO_OK,
        .way = FROM_CLIENT,
        .expected = {
            .info = { .head_len = CIFS_HEADER_SIZE, .payload = 0xee - CIFS_HEADER_SIZE},
            .command = SMB_COM_SESSION_SETUP_ANDX,
            .user = "Tototest",
            .set_values = SMB_USER,
        },
    },

};

#define CHECK_SMB_SET(INFO, EXPECTED, MASK) \
    check_set_values(INFO->set_values, EXPECTED->set_values, MASK, set_value_2_str);

static unsigned cur_test;

static bool compare_expected_cifs(struct cifs_proto_info const *const info,
        struct cifs_proto_info const *const expected)
{
    CHECK_INT(info->info.head_len, expected->info.head_len);
    CHECK_INT(info->info.payload, expected->info.payload);

    CHECK_SMB_SET(info, expected, SMB_DOMAIN);

    CHECK_INT(info->command, expected->command);
    if (VALUES_ARE_SET(info, SMB_DOMAIN))
        CHECK_STR(info->domain, expected->domain);
    if (VALUES_ARE_SET(info, SMB_USER))
        CHECK_STR(info->user, expected->user);

    return 0;
}

static void cifs_info_check(struct proto_subscriber unused_ *s, struct proto_info const *info_,
        size_t unused_ cap_len, uint8_t const unused_ *packet, struct timeval const unused_ *now)
{
    // Check info against parse_tests[cur_test].expected
    struct cifs_proto_info const *const info = DOWNCAST(info_, info, cifs_proto_info);
    struct cifs_proto_info const *const expected = &parse_tests[cur_test].expected;
    assert(!compare_expected_cifs(info, expected));
}

static void parse_check(void)
{
    struct timeval now;
    timeval_set_now(&now);
    struct parser *parser = proto_cifs->ops->parser_new(proto_cifs);
    struct proto_subscriber sub;
    hook_subscriber_ctor(&pkt_hook, &sub, cifs_info_check);

    for (cur_test = 0; cur_test < NB_ELEMS(parse_tests); cur_test++) {
        struct parse_test const *test = parse_tests + cur_test;
        printf("Check packet %d of size 0x%x (%d)\n", cur_test, test->size, test->size);
        enum proto_parse_status ret = cifs_parse(parser, NULL, test->way, test->packet, test->size,
                test->size, &now, test->size, test->packet);
        assert(ret == test->ret);
    }
}

int main(void)
{
    log_init();
    ext_init();
    mutex_init();
    objalloc_init();
    proto_init();
    pkt_wait_list_init();
    ref_init();
    cap_init();
    eth_init();
    ip_init();
    ip6_init();
    tcp_init();
    cifs_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("cifs_check.log");

    parse_check();

    cifs_fini();
    tcp_fini();
    ip6_fini();
    ip_fini();
    eth_fini();
    cap_fini();
    ref_fini();
    pkt_wait_list_fini();
    proto_fini();
    objalloc_fini();
    mutex_fini();
    ext_fini();
    log_fini();
    return EXIT_SUCCESS;
}

