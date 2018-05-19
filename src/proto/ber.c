// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2018, SecurActive.
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
#include <stdlib.h>
#include "junkie/tools/tempstr.h"
#include "junkie/proto/ber.h"

enum ber_class {
    BER_UNIVERSAL = 0, BER_APPLICATION = 1,
    BER_CONTEXT_SPEC = 2, BER_PRIVATE = 3,
};

static char const *ber_class_2_str(enum ber_class c)
{
    switch (c) {
        case BER_UNIVERSAL: return "universal";
        case BER_APPLICATION: return "application";
        case BER_CONTEXT_SPEC: return "context-specific";
        case BER_PRIVATE: return "private";
    }
    assert(!"Invalid BER class");
}

enum ber_type {
    BER_INTEGER = 2,
    BER_BIT_STRING = 3,
    BER_OCTET_STRING = 4,
    BER_NULL = 5,
    BER_OBJECT_IDENTIFIER = 6,
    BER_UTF8STRING = 12,
    BER_SEQUENCE = 16,
    BER_SET = 17,
    BER_PRINTABLE_STRING = 19,
    BER_T61_STRING = 20,
    BER_VIDEOTEXT_STRING = 21,
    BER_IA5_STRING = 22,
    BER_UTC_TIME = 23,
    BER_GENERALIZED_TIME = 24,
    BER_VISIBLE_STRING = 26,
    BER_UNIVERSAL_STRING = 28,
};

struct ber_tag {
    enum ber_class class;
    bool constructed;
    unsigned tag;
    size_t length;
};

static char const *ber_tag_2_str(struct ber_tag *t)
{
    char const *tagname = tempstr_printf("%s of type %u", ber_class_2_str(t->class), t->tag);

    // We know the name of some tags
    if (t->class == BER_UNIVERSAL) {
        static char const *universal_tagnames[] = {
            [BER_INTEGER] = "integer",
            [BER_BIT_STRING] = "bit string",
            [BER_OCTET_STRING] = "octet string",
            [BER_NULL] = "null",
            [BER_OBJECT_IDENTIFIER] = "object identifier",
            [BER_UTF8STRING] = "UTF8 string",
            [BER_SEQUENCE] = "sequence",
            [BER_SET] = "set",
            [BER_PRINTABLE_STRING] = "printable string",
            [BER_T61_STRING] = "T61 string",
            [BER_VIDEOTEXT_STRING] = "videotext string",
            [BER_IA5_STRING] = "IA5 string",
            [BER_UTC_TIME] = "UTC time",
            [BER_VISIBLE_STRING] = "visible string",
            [BER_UNIVERSAL_STRING] = "universal string",
        };
        if (t->tag < NB_ELEMS(universal_tagnames) && universal_tagnames[t->tag] != NULL) {
            tagname = universal_tagnames[t->tag];
        }
    }

    return tempstr_printf("%s%s of length %zu", t->constructed ? "constructed ":"", tagname, t->length);
}

static enum proto_parse_status ber_decode_tag(struct cursor *c, struct ber_tag *t)
{
    // Tag
    if (c->cap_len < 1) return PROTO_TOO_SHORT;
    uint_least8_t b = cursor_read_u8(c);
    t->tag = b & 0x1f;
    t->constructed = !!(b & 0x20);
    t->class = b >> 6;
    if (unlikely_(t->tag == 0x1f)) {   // high tag number form
        t->tag = 0;
        do {
            t->tag <<= 7U;
            if (c->cap_len < 1) return PROTO_TOO_SHORT;
            b = cursor_read_u8(c);
            if (b & 0x80U) {
                t->tag |= b & 0x7fU;
            } else {
                t->tag |= b;
                break;
            }
        } while (1);
    }

    // Length
    if (c->cap_len < 1) return PROTO_TOO_SHORT;
    t->length = cursor_read_u8(c);
    if (t->length >= 0x80U) {    // long form
        unsigned nb_bytes = t->length & 0x7fU;
        t->length = 0;
        while (nb_bytes--) {
            t->length <<= 8U;
            if (c->cap_len < 1) return PROTO_TOO_SHORT;
            t->length |= cursor_read_u8(c);
        }
    }

    return PROTO_OK;
}

enum proto_parse_status ber_skip(struct cursor *c)
{
    struct ber_tag t;
    enum proto_parse_status status = ber_decode_tag(c, &t);
    if (status != PROTO_OK) return status;

    // Skip value
    if (c->cap_len < t.length) return PROTO_TOO_SHORT;
    cursor_drop(c, t.length);

    return PROTO_OK;
}

enum proto_parse_status ber_copy(struct cursor *c, void *dest, size_t *nb_bytes, size_t max_sz)
{
    struct ber_tag t;
    enum proto_parse_status status = ber_decode_tag(c, &t);
    if (status != PROTO_OK) return status;

    if (c->cap_len < t.length) return PROTO_TOO_SHORT;
    if (max_sz < t.length) return PROTO_PARSE_ERR;
    cursor_copy(dest, c, t.length);
    *nb_bytes = t.length;

    return PROTO_OK;
}

static enum proto_parse_status ber_read_digit(struct cursor *c, uint8_t *res)
{
    *res = cursor_read_u8(c);
    if (*res < '0' || *res > '9') return PROTO_PARSE_ERR;
    *res -= '0';
    return PROTO_OK;
}

static enum proto_parse_status ber_read_2digits(struct cursor *c, uint8_t *res)
{
    enum proto_parse_status status;
    uint8_t d;
    if (PROTO_OK != (status = ber_read_digit(c, &d))) return status;
    if (PROTO_OK != (status = ber_read_digit(c, res))) return status;
    *res += d * 10U;
    return PROTO_OK;
}

char const *ber_time_2_str(struct ber_time const *t)
{
    return tempstr_printf("%04"PRIu16"-%02"PRIu8"-%02"PRIu8" %02"PRIu8":%02"PRIu8":%02"PRIu8,
            t->year, t->month, t->day, t->hour, t->min, t->sec);
}

static enum proto_parse_status ber_extract_utc_time(struct cursor *c, size_t len, struct ber_time *t, bool generalized)
{
    enum proto_parse_status status;

    uint8_t century = 0;
    if (generalized) {
        if (len != 15) return PROTO_PARSE_ERR;
        /* For the purposes of this profile, GeneralizedTime values MUST be
         * expressed in Greenwich Mean Time (Zulu) and MUST include seconds
         * (i.e., times are YYYYMMDDHHMMSSZ), even where the number of seconds
         * is zero.  GeneralizedTime values MUST NOT include fractional seconds. */
        if (PROTO_OK != (status = ber_read_2digits(c, &century))) return status;
    } else {
        if (len != 13) return PROTO_PARSE_ERR;
        /* For the purposes of this profile, UTCTime values MUST be expressed in
         * Greenwich Mean Time (Zulu) and MUST include seconds (i.e., times are
         * YYMMDDHHMMSSZ), even where the number of seconds is zero. -- RFC 5280 */
    }

    uint8_t year;
    if (PROTO_OK != (status = ber_read_2digits(c, &year))) return status;
    if (PROTO_OK != (status = ber_read_2digits(c, &t->month))) return status;
    if (PROTO_OK != (status = ber_read_2digits(c, &t->day))) return status;
    if (PROTO_OK != (status = ber_read_2digits(c, &t->hour))) return status;
    if (PROTO_OK != (status = ber_read_2digits(c, &t->min))) return status;
    if (PROTO_OK != (status = ber_read_2digits(c, &t->sec))) return status;
    char z = cursor_read_u8(c);
    if (z != 'z' && z != 'Z') return PROTO_PARSE_ERR;

    if (generalized) {
        t->year = century * 100U + year;
    } else {
        /* Conforming systems MUST interpret the year field (YY) as follows:
         * Where YY is greater than or equal to 50, the year SHALL be
         * interpreted as 19YY; and
         * Where YY is less than 50, the year SHALL be interpreted as 20YY. */
        t->year = year + (year >= 50 ? 1900 : 2000);
    }

    return PROTO_OK;
}

enum proto_parse_status ber_extract_time(struct cursor *c, struct ber_time *time)
{
    struct ber_tag t;
    enum proto_parse_status status = ber_decode_tag(c, &t);
    if (status != PROTO_OK) return status;

    if (c->cap_len < t.length) return PROTO_TOO_SHORT;
    if (t.class != BER_UNIVERSAL) return PROTO_PARSE_ERR;
    if (t.tag == BER_UTC_TIME) {
        return ber_extract_utc_time(c, t.length, time, false);
    } else if (t.tag == BER_GENERALIZED_TIME) {
        return ber_extract_utc_time(c, t.length, time, true);
    } else return PROTO_PARSE_ERR;

    return PROTO_OK;
}

enum proto_parse_status ber_skip_optional(struct cursor *c, unsigned tag)
{
    struct cursor c_save = *c;
    struct ber_tag t;
    enum proto_parse_status status = ber_decode_tag(c, &t);
    if (status != PROTO_OK) return status;

    if (t.tag == tag) {
        // Skip the value
        if (c->cap_len < t.length) return PROTO_TOO_SHORT;
        cursor_drop(c, t.length);
    } else {    // rewind
        *c = c_save;
    }

    return PROTO_OK;
}

enum proto_parse_status ber_enter(struct cursor *c)
{
    struct ber_tag t;
    enum proto_parse_status status = ber_decode_tag(c, &t);
    if (status != PROTO_OK) return status;

    if (! t.constructed) {
        SLOG(LOG_DEBUG, "BER tag %s must be constructed", ber_tag_2_str(&t));
        return PROTO_PARSE_ERR;
    }

    return PROTO_OK;
}

enum proto_parse_status ber_decode_string(struct cursor *c, size_t out_sz, char *out)
{
    struct ber_tag t;
    enum proto_parse_status status = ber_decode_tag(c, &t);
    if (status != PROTO_OK) return status;
    if (t.constructed || t.class != BER_UNIVERSAL) { // FIXME: in BER (not DER), printable string is in fact allowed to be constructed as sequence of bitstrings
err:    SLOG(LOG_DEBUG, "BER tag %s is not a string", ber_tag_2_str(&t));
        return PROTO_PARSE_ERR;
    }

    if (t.length > c->cap_len) return PROTO_TOO_SHORT;

    switch (t.tag) {
        case BER_UTF8STRING:
        case BER_PRINTABLE_STRING:
        case BER_T61_STRING:
        case BER_IA5_STRING:
        case BER_VIDEOTEXT_STRING:
        case BER_VISIBLE_STRING:
        case BER_UNIVERSAL_STRING:
            out_sz = MIN(t.length, out_sz-1);
            memcpy(out, c->head, out_sz);
            out[out_sz] = '\0';
            break;
        default:
            goto err;
    }

    // pass the value
    cursor_drop(c, t.length);

    return PROTO_OK;
}

enum proto_parse_status ber_foreach(struct cursor *c, foreach_fn *f, void *d)
{
    struct ber_tag t;
    enum proto_parse_status status = ber_decode_tag(c, &t);
    if (status != PROTO_OK) return status;

    if (! t.constructed) {
        SLOG(LOG_DEBUG, "BER tag %s must be constructed", ber_tag_2_str(&t));
        return PROTO_PARSE_ERR;
    }

    uint8_t const *end = c->head + t.length;
    while (status == PROTO_OK && c->cap_len > 0 && c->head < end) {
        status = f(c, d);
    }
    if (c->head > end) return PROTO_PARSE_ERR;

    // Skip what's left
    size_t left = end - c->head;
    if (c->cap_len < left) return PROTO_TOO_SHORT;
    cursor_drop(c, left);

    return status;
}
