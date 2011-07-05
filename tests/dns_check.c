// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#undef NDEBUG
#include <assert.h>
#include <time.h>
#include <junkie/cpp.h>
#include <junkie/tools/miscmacs.h>
#include <junkie/tools/mallocer.h>
#include <junkie/proto/pkt_wait_list.h>
#include <junkie/proto/udp.h>
#include <junkie/proto/tcp.h>
#include <junkie/proto/ip.h>
#include <junkie/proto/eth.h>
#include <junkie/proto/cap.h>
#include "lib.h"
#include "proto/dns.c"

/*
 * Parse Check
 */

static struct parse_test {
	uint8_t const *packet;
	size_t size;
	struct dns_proto_info expected;
} parse_tests[] = {
	{
		.packet = (uint8_t const []) {
			0x8c, 0xcf, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x6c, 0x65, 0x6d,
			0x6f, 0x6e, 0x64, 0x65, 0x02, 0x66, 0x72, 0x00, 0x00, 0x1c, 0x00, 0x01,
		},
		.size = 16+12,
		.expected = {
			.info = { .head_len = 16+12, .payload = 0 },
			.query = true, .transaction_id = 0x8ccf, .error_code = 0,
			.request_type = DNS_TYPE_AAAA, .dns_class = DNS_CLASS_IN,
			.name = "lemonde.fr"
		},
	}, {
        .packet = (uint8_t const []) {
            0x8c, 0xcf, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x07, 0x6c, 0x65, 0x6d,
            0x6f, 0x6e, 0x64, 0x65, 0x02, 0x66, 0x72, 0x00, 0x00, 0x1c, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x06,
            0x00, 0x01, 0x00, 0x00, 0x02, 0x58, 0x00, 0x30, 0x03, 0x6e, 0x73, 0x31, 0x06, 0x74, 0x65, 0x2d,
            0x64, 0x6e, 0x73, 0x03, 0x6e, 0x65, 0x74, 0x00, 0x09, 0x64, 0x6e, 0x73, 0x6d, 0x61, 0x73, 0x74,
            0x65, 0x72, 0xc0, 0x2c, 0x77, 0xbf, 0x85, 0x49, 0x00, 0x00, 0x38, 0x40, 0x00, 0x00, 0x0e, 0x10,
            0x00, 0x09, 0x3a, 0x80, 0x00, 0x00, 0x38, 0x40,
        },
        .size = 16*5+8,
        .expected = {
            .info = { .head_len = 16*5+8, .payload = 0 },
            .query = false, .transaction_id = 0x8ccf, .error_code = 0,
            .request_type = DNS_TYPE_AAAA, .dns_class = DNS_CLASS_IN,
            .name = "lemonde.fr"
        },
    }, {
        .packet = (uint8_t const []) {
            0x12, 0x78, 0x85, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x23, 0x63, 0x65, 0x64,
            0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x73, 0x71, 0x75, 0x65, 0x70, 0x61,
            0x73, 0x64, 0x65, 0x78, 0x69, 0x73, 0x74, 0x65, 0x72, 0x2d, 0x68, 0x61, 0x68, 0x61, 0x68, 0x61,
            0x03, 0x6f, 0x72, 0x67, 0x04, 0x6c, 0x61, 0x62, 0x6f, 0x0b, 0x73, 0x65, 0x63, 0x75, 0x72, 0x61,
            0x63, 0x74, 0x69, 0x76, 0x65, 0x03, 0x6c, 0x61, 0x6e, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x34,
            0x00, 0x06, 0x00, 0x01, 0x00, 0x01, 0x51, 0x80, 0x00, 0x30, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
            0x68, 0x6f, 0x73, 0x74, 0x00, 0x04, 0x72, 0x6f, 0x6f, 0x74, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
            0x68, 0x6f, 0x73, 0x74, 0xc0, 0x34, 0x30, 0x29, 0x45, 0xc1, 0x00, 0x00, 0x70, 0x80, 0x00, 0x00,
            0x03, 0x0c, 0x00, 0x09, 0x3a, 0x80, 0x00, 0x01, 0x51, 0x80,
        },
        .size = 16*8+10,
        .expected = {
            .info = { .head_len = 16*8+10, .payload = 0 },
            .query = false, .transaction_id = 0x1278, .error_code = 3,
            .request_type = DNS_TYPE_A, .dns_class = DNS_CLASS_IN,
            .name = "cedomainenerisquepasdexister-hahaha.org.labo.securactive.lan"
        },
    }, {    // A NetBios type DNS query (NBNS)
        .packet = (uint8_t const []) {
            0xa3, 0x7a, 0x01, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x46, 0x41, 0x45, 
            0x44, 0x43, 0x4e, 0x45, 0x45, 0x45, 0x46, 0x43, 0x4e, 0x45, 0x45, 0x45, 0x46, 0x45, 0x4d, 0x46, 
            0x41, 0x45, 0x49, 0x45, 0x4a, 0x45, 0x4f, 0x45, 0x46, 0x43, 0x41, 0x42, 0x4d, 0x00, 0x00, 0x20, 
            0x00, 0x01,
        },
        .size = 16*3+2,
        .expected = {
            .info = { .head_len = 16*3+2, .payload = 0 },
            .query = true, .transaction_id = 0xa37a, .error_code = 0,
            .request_type = DNS_TYPE_NBNS, .dns_class = DNS_CLASS_IN,
            .name = "PC-DE-DELPHINE \x1c"
        },
    }, {
        .packet = (uint8_t const []) {
            0xf9, 0x39, 0x01, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x45, 0x42, 0x46,
            0x45, 0x45, 0x49, 0x45, 0x46, 0x45, 0x4f, 0x45, 0x46, 0x43, 0x4e, 0x45, 0x47, 0x45, 0x4a, 0x45,
            0x4d, 0x45, 0x46, 0x46, 0x44, 0x45, 0x46, 0x46, 0x43, 0x46, 0x47, 0x41, 0x41, 0x00, 0x00, 0x20,
            0x00, 0x01,
        },
        .size = 16*3+2,
        .expected = {
            .info = { .head_len = 16*3+2, .payload = 0 },
            .query = true, .transaction_id = 0xf939, .error_code = 0,
            .request_type = DNS_TYPE_NBNS, .dns_class = DNS_CLASS_IN,
            .name = "ATHENE-FILESERV"
        },
    }, 
};

static unsigned current_test;

static int dns_info_check(struct proto_info const *info_, size_t unused_ cap_len, uint8_t const unused_ *packet)
{
	struct dns_proto_info const *const info = DOWNCAST(info_, info, dns_proto_info);
	struct dns_proto_info const *const expected = &parse_tests[current_test].expected;

#	define CHECK(field) assert(info->field == expected->field);
	CHECK(info.head_len);
	CHECK(info.payload);
	CHECK(query);
	CHECK(transaction_id);
	CHECK(error_code);
	CHECK(request_type);
	CHECK(dns_class);
	assert(0 == strcmp(info->name, expected->name));

	return 0;
}

static void parse_check(void)
{
    struct timeval now;
    timeval_set_now(&now);
    struct parser *dns_parser = proto_dns->ops->parser_new(proto_dns);
    assert(dns_parser);

    for (current_test = 0; current_test < NB_ELEMS(parse_tests); current_test++) {
        struct parse_test const *test = parse_tests + current_test;
        printf("Testing packet %u...", current_test);
        int ret = dns_parse(dns_parser, NULL, 0, test->packet, test->size, test->size, &now, dns_info_check, test->size, test->packet);
        assert(0 == ret);
		printf("Ok\n");
    }

    parser_unref(dns_parser);
}

/*
 * QNAME Extraction
 */

static void qname_check(void)
{
    static struct qname_test {
        uint8_t const payload[256];
        size_t len;
        char const *expected;
    } tests[] = {
        {
            .payload = {
                2, 'h', 'g', 2, 'r', 'd',
                11, 's', 'e', 'c', 'u', 'r', 'a', 'c', 't', 'i', 'v', 'e',
                3, 'n', 'e', 't', '\0'
            },
            .len = 23,
            .expected = "hg.rd.securactive.net",
        }, {
            .payload = {
                3 /*here is the error */ , 'h', 'g', 2, 'r', 'd',
                11, 's', 'e', 'c', 'u', 'r', 'a', 'c', 't', 'i', 'v', 'e',
                3, 'n', 'e', 't', '\0'
            },
            .len = 23,
            .expected = NULL,
        }, {
            .payload = { 0 },
            .len = 1,
            .expected = "",
        }, {
            .payload = { 12 },
            .len = 1,
            .expected = NULL,
        }, {
            .payload = { 2, 'a', 'a', -1, 'b', 'b', 'b', 0 },
            .len = 8,
            .expected = NULL,
        }, {
            .payload = { 2, 'a', 'a', 255, 'b', 'b', 'b', 0 },
            .len = 8,
            .expected = NULL,
        },
    };

    for (unsigned t = 0; t < NB_ELEMS(tests); t++) {
        struct qname_test *test = tests+t;
        char tmp[256];
        printf("Testing QNAME %u...", t);
        ssize_t ret = extract_qname(tmp, sizeof(tmp), test->payload, test->len, false);
        if (test->expected) {
            assert(ret >= 0);
            assert(0 == strcmp(tmp, test->expected));
        }
        printf("Ok\n");
    }
}

int main(void)
{
    log_init();
    mallocer_init();
    pkt_wait_list_init();
    ref_init();
    cap_init();
    eth_init();
    ip_init();
    ip6_init();
    udp_init();
    tcp_init();
    dns_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("dns_check.log");

    parse_check();
    qname_check();
    stress_check(proto_dns);

    dns_fini();
    tcp_fini();
    udp_fini();
    ip6_fini();
    ip_fini();
    eth_fini();
    cap_fini();
    ref_fini();
    pkt_wait_list_fini();
    mallocer_fini();
    log_fini();
    return EXIT_SUCCESS;
}

