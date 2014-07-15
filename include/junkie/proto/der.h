// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef DER_H_150714
#define DER_H_150714

#include <stdint.h>
#include "junkie/proto/proto.h"
#include "junkie/proto/cursor.h"

enum der_class_identifier {
    DER_UNIVERSAL        = 0x0,
    DER_APPLICATION      = 0x1,
    DER_CONTEXT_SPECIFIC = 0x2,
    DER_PRIVATE          = 0x3,
};

enum der_type {
    DER_PRIMITIVE        = 0x0,
    DER_CONSTRUCTED      = 0x1,
};

enum der_class_tag {
    DER_EOC               = 0x00,
    DER_BOOLEAN           = 0x01,
    DER_INTEGER           = 0x02,
    DER_BIT_STRING        = 0x03,
    DER_OCTET_STRING      = 0x04,
    DER_NULL              = 0x05,
    DER_OBJECT_IDENTIFIER = 0x06,
    DER_OBJECT_DESCRIPTOR = 0x07,
    DER_EXTERNAL          = 0x08,
    DER_REAL              = 0x09,
    DER_ENUMERATED        = 0x0a,
    DER_EMBEDDED_PDV      = 0x0b,
    DER_UTF8STRING        = 0x0c,
    DER_RELATIVE_OID      = 0x0d,
    DER_SEQUENCE          = 0x10,
    DER_SET               = 0x11,
    DER_NUMERIC_STRING    = 0x12,
    DER_PRINTABLE_STRING  = 0x13,
    DER_T61_STRING        = 0x14,
    DER_VIDEOTEX_STRING   = 0x15,
    DER_IA5_STRING        = 0x16,
    DER_UTC_TIME          = 0x17,
    DER_GENERALIZED_TIME  = 0x18,
    DER_GRAPHIC_STRING    = 0x19,
    DER_VISIBLE_STRING    = 0x1a,
    DER_GENERAL_STRING    = 0x1b,
    DER_UNIVERSAL_STRING  = 0x1c,
    DER_CHARACTER_STRING  = 0x1d,
    DER_BMP_STRING        = 0x1e,
    DER_LONG_FORM         = 0x1f,
};

struct der {
    enum der_class_identifier class_identifier:2;
    enum der_type type:1;
    enum der_class_tag class_tag:5;
    uint8_t length;
    uint8_t const *value;
};

enum proto_parse_status cursor_read_der(struct cursor *cursor, struct der *der);

char *der_2_str(struct der *der);

#endif

