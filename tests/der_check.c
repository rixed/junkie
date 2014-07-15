// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab

#include <stdlib.h>
#include "junkie/proto/der.h"
#include "lib_test_junkie.h"

static struct parse_test {
    size_t size;
    uint8_t const packet[64];
    struct der expected;
} parse_tests [] = {
    {
        .size = 0xc,
        .packet = {
            0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a
        },
        .expected = {
            .class_identifier = DER_UNIVERSAL,
            .type = DER_PRIMITIVE,
            .class_tag = DER_OBJECT_IDENTIFIER,
            .length = 0x0a,
        },
    },
};

static int der_check(struct der *der, struct der *expected)
{
    CHECK_INT(der->class_identifier, expected->class_identifier);
    CHECK_INT(der->type, expected->type);
    CHECK_INT(der->class_tag, expected->class_tag);
    CHECK_INT(der->length, expected->length);
    return 0;
}

static void parse_check()
{
    for (unsigned i = 0; i < NB_ELEMS(parse_tests); i++) {
        struct cursor cursor;
        struct parse_test parse_test = parse_tests[i];
        cursor_ctor(&cursor, parse_test.packet, parse_test.size);
        struct der der;
        enum proto_parse_status ret = cursor_read_der(&cursor, &der);
        assert(PROTO_OK == ret);
        assert(0 == der_check(&der, &parse_test.expected));
    }
}

int main(void)
{
    log_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("der_check.log");

    parse_check();

    log_fini();
}

