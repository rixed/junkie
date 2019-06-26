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
#include <string.h>
#include "junkie/tools/log.h"
#include "junkie/proto/cursor.h"

extern inline void cursor_rollback(struct cursor *, size_t);
extern inline void cursor_ctor(struct cursor *, uint8_t const *, size_t);
extern inline uint_least8_t cursor_read_u8(struct cursor *);
extern inline uint_least16_t cursor_read_u16n(struct cursor *);
extern inline uint_least16_t cursor_read_u16le(struct cursor *);
extern inline uint_least32_t cursor_read_u24n(struct cursor *);
extern inline uint_least32_t cursor_read_u24le(struct cursor *);
extern inline uint_least32_t cursor_read_u32n(struct cursor *);
extern inline uint_least32_t cursor_read_u32le(struct cursor *);
extern inline uint_least64_t cursor_read_u64n(struct cursor *);
extern inline uint_least64_t cursor_read_u64le(struct cursor *);
extern inline void cursor_copy(void *, struct cursor *, size_t);
extern inline void cursor_drop(struct cursor *, size_t);
extern inline bool cursor_is_empty(struct cursor const *);

enum proto_parse_status cursor_read_string(struct cursor *cursor, char **str_, size_t max_len)
{
    char *str = tempstr();
    unsigned len;
    if (max_len > TEMPSTR_SIZE-1) max_len = TEMPSTR_SIZE-1;

    for (len = 0; len < max_len; len ++) {
        CHECK_LEN(cursor, 1, len);
        uint8_t c = cursor_read_u8(cursor);
        if (c == '\0') break;
        str[len] = c;
    }
    if (len == max_len) {
        cursor_rollback(cursor, len);
        return PROTO_TOO_SHORT;
    }

    str[len] = '\0';

    SLOG(LOG_DEBUG, "Reading string '%s'", str);

    if (str_) *str_ = str;
    return PROTO_OK;
}

enum proto_parse_status cursor_read_fix_int_n(struct cursor *cursor, uint_least64_t *out_res, unsigned len)
{
    uint_least64_t res;
    if (cursor->cap_len < len) return PROTO_TOO_SHORT;
    switch (len) {
        case 0:
            res = 0;
            break;
        case 1:
            res = cursor_read_u8(cursor);
            break;
        case 2:
            res = cursor_read_u16n(cursor);
            break;
        case 3:
            res = cursor_read_u24n(cursor);
            break;
        case 4:
            res = cursor_read_u32n(cursor);
            break;
        case 8:
            res = cursor_read_u64n(cursor);
            break;
        default:
            SLOG(LOG_DEBUG, "Can't read a %d bytes long number", len);
            return PROTO_PARSE_ERR;
    }
    if (out_res) *out_res = res;
    return PROTO_OK;
}

enum proto_parse_status cursor_read_fix_int_le(struct cursor *cursor, uint_least64_t *out_res, unsigned len)
{
    uint_least64_t res;
    if (cursor->cap_len < len) return PROTO_TOO_SHORT;
    switch (len) {
        case 0:
            res = 0;
            break;
        case 1:
            res = cursor_read_u8(cursor);
            break;
        case 2:
            res = cursor_read_u16le(cursor);
            break;
        case 3:
            res = cursor_read_u24le(cursor);
            break;
        case 4:
            res = cursor_read_u32le(cursor);
            break;
        case 8:
            res = cursor_read_u64le(cursor);
            break;
        default:
            SLOG(LOG_DEBUG, "Can't read a %d bytes long number", len);
            return PROTO_PARSE_ERR;
    }
    if (out_res) *out_res = res;
    return PROTO_OK;
}
