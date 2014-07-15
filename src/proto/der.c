// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2014, SecurActive.
 *
 * This file is part of Junkie.
 *
 * Junkie is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Junkie is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Junkie.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "junkie/proto/der.h"
#include "junkie/tools/tempstr.h"
#include "junkie/tools/log.h"
#include <inttypes.h>

static char *der_class_identifier_2_str(enum der_class_identifier der_class_identifier)
{
    switch (der_class_identifier) {
        case DER_UNIVERSAL        : return "DER_UNIVERSAL";
        case DER_APPLICATION      : return "DER_APPLICATION";
        case DER_CONTEXT_SPECIFIC : return "DER_CONTEXT_SPECIFIC";
        case DER_PRIVATE          : return "DER_PRIVATE";
        default                   : return tempstr_printf("Unknown (0x%"PRIx32")", der_class_identifier);
    }
}

static char *der_type_2_str(enum der_type der_type)
{
    switch (der_type) {
        case DER_PRIMITIVE        : return "DER_PRIMITIVE";
        case DER_CONSTRUCTED      : return "DER_CONSTRUCTED";
        default                   : return tempstr_printf("Unknown (0x%"PRIx32")", der_type);
    }
}

static char *der_class_tag_2_str(enum der_class_tag der_class_tag)
{
    switch (der_class_tag) {
        case DER_EOC               : return "DER_EOC";
        case DER_BOOLEAN           : return "DER_BOOLEAN";
        case DER_INTEGER           : return "DER_INTEGER";
        case DER_BIT_STRING        : return "DER_BIT_STRING";
        case DER_OCTET_STRING      : return "DER_OCTET_STRING";
        case DER_NULL              : return "DER_NULL";
        case DER_OBJECT_IDENTIFIER : return "DER_OBJECT_IDENTIFIER";
        case DER_OBJECT_DESCRIPTOR : return "DER_OBJECT_DESCRIPTOR";
        case DER_EXTERNAL          : return "DER_EXTERNAL";
        case DER_REAL              : return "DER_REAL";
        case DER_ENUMERATED        : return "DER_ENUMERATED";
        case DER_EMBEDDED_PDV      : return "DER_EMBEDDED_PDV";
        case DER_UTF8STRING        : return "DER_UTF8STRING";
        case DER_RELATIVE_OID      : return "DER_RELATIVE_OID";
        case DER_SEQUENCE          : return "DER_SEQUENCE";
        case DER_SET               : return "DER_SET";
        case DER_NUMERIC_STRING    : return "DER_NUMERIC_STRING";
        case DER_PRINTABLE_STRING  : return "DER_PRINTABLE_STRING";
        case DER_T61_STRING        : return "DER_T61_STRING";
        case DER_VIDEOTEX_STRING   : return "DER_VIDEOTEX_STRING";
        case DER_IA5_STRING        : return "DER_IA5_STRING";
        case DER_UTC_TIME          : return "DER_UTC_TIME";
        case DER_GENERALIZED_TIME  : return "DER_GENERALIZED_TIME";
        case DER_GRAPHIC_STRING    : return "DER_GRAPHIC_STRING";
        case DER_VISIBLE_STRING    : return "DER_VISIBLE_STRING";
        case DER_GENERAL_STRING    : return "DER_GENERAL_STRING";
        case DER_UNIVERSAL_STRING  : return "DER_UNIVERSAL_STRING";
        case DER_CHARACTER_STRING  : return "DER_CHARACTER_STRING";
        case DER_BMP_STRING        : return "DER_BMP_STRING";
        case DER_LONG_FORM         : return "DER_LONG_FORM";
        default                    : return tempstr_printf("Unknown (0x%"PRIx32")", der_class_tag);
    }
}

char *der_2_str(struct der *der)
{
    char *str = tempstr_printf("Der class %s, type: %s, class tag: %s, size %"PRIu8,
            der_class_identifier_2_str(der->class_identifier),
            der_type_2_str(der->type),
            der_class_tag_2_str(der->class_tag),
            der->length);
    return str;
}

#define DER_CLASS_IDENTIFIER 0xc0
#define DER_TYPE 0x40
#define DER_CLASS_TAG 0x1f

enum proto_parse_status cursor_read_der(struct cursor *cursor, struct der *der)
{
    uint8_t der_header = cursor_read_u8(cursor);
    der->class_identifier = der_header & DER_CLASS_IDENTIFIER;
    der->type = der_header & DER_TYPE;
    der->class_tag = der_header & DER_CLASS_TAG;
    der->length = cursor_read_u8(cursor);
    SLOG(LOG_DEBUG, "Parsed der %s, %"PRIx16, der_2_str(der), der_header);
    if (der->length > cursor->cap_len) return PROTO_TOO_SHORT;
    der->value = cursor->head;
    return PROTO_OK;
}

