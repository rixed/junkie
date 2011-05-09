// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2010, SecurActive.
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
#include <junkie/tools/log.h>
#include <junkie/proto/cursor.h>

void cursor_rollback(struct cursor *cursor, size_t n)
{
    cursor->cap_len += n;
    cursor->head -= n;
}

void cursor_ctor(struct cursor *cursor, uint8_t const *head, size_t cap_len)
{
    cursor->head = head;
    cursor->cap_len = cap_len;
}

uint_least8_t cursor_read_u8(struct cursor *cursor)
{
    assert(cursor->cap_len >= 1);
    cursor->cap_len --;
    SLOG(LOG_DEBUG, "Reading byte 0x%x, %zu left", *cursor->head, cursor->cap_len);
    return *cursor->head++;
}

uint_least16_t cursor_read_u16n(struct cursor *cursor)
{
    uint_least32_t a = cursor_read_u8(cursor);
    uint_least32_t b = cursor_read_u8(cursor);
    return (a << 8) | b;
}

uint_least16_t cursor_read_u16(struct cursor *cursor)
{
    uint_least32_t a = cursor_read_u8(cursor);
    uint_least32_t b = cursor_read_u8(cursor);
    return a | (b << 8);
}

uint_least32_t cursor_read_u24(struct cursor *cursor)
{
    uint_least32_t a = cursor_read_u8(cursor);
    uint_least32_t b = cursor_read_u8(cursor);
    uint_least32_t c = cursor_read_u8(cursor);
    return a | (b << 8) | (c << 16);
}

uint_least32_t cursor_read_u32n(struct cursor *cursor)
{
    uint_least32_t a = cursor_read_u16n(cursor);
    uint_least32_t b = cursor_read_u16n(cursor);
    return (a << 16) | b;
}

uint_least32_t cursor_read_u32(struct cursor *cursor)
{
    uint_least32_t a = cursor_read_u16(cursor);
    uint_least32_t b = cursor_read_u16(cursor);
    return a | (b << 16);
}

uint_least64_t cursor_read_u64(struct cursor *cursor)
{
    uint_least64_t a = cursor_read_u32(cursor);
    uint_least64_t b = cursor_read_u32(cursor);
    return a | (b << 32);
}

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

void cursor_drop(struct cursor *cursor, size_t n)
{
    assert(cursor->cap_len >= n);
    cursor->cap_len -= n;
    cursor->head += n;
}

bool cursor_is_empty(struct cursor const *cursor)
{
    return cursor->cap_len == 0;
}

