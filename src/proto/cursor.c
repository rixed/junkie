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
#include <string.h>
#include "junkie/tools/log.h"
#include "junkie/proto/cursor.h"

void cursor_rollback(struct cursor *cursor, size_t n)
{
    SLOG(LOG_DEBUG, "Rollback %zu bytes", n);
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

uint_least16_t cursor_read_u16le(struct cursor *cursor)
{
    uint_least32_t a = cursor_read_u8(cursor);
    uint_least32_t b = cursor_read_u8(cursor);
    return a | (b << 8);
}

uint_least32_t cursor_read_u24n(struct cursor *cursor)
{
    uint_least32_t a = cursor_read_u8(cursor);
    uint_least32_t b = cursor_read_u8(cursor);
    uint_least32_t c = cursor_read_u8(cursor);
    return (a << 16) | (b << 8) | c;
}

uint_least32_t cursor_read_u24le(struct cursor *cursor)
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

uint_least32_t cursor_read_u32le(struct cursor *cursor)
{
    uint_least32_t a = cursor_read_u16le(cursor);
    uint_least32_t b = cursor_read_u16le(cursor);
    return a | (b << 16);
}

uint_least64_t cursor_read_u64n(struct cursor *cursor)
{
    uint_least64_t a = cursor_read_u32le(cursor);
    uint_least64_t b = cursor_read_u32le(cursor);
    return (a << 32) | b;
}

uint_least64_t cursor_read_u64le(struct cursor *cursor)
{
    uint_least64_t a = cursor_read_u32le(cursor);
    uint_least64_t b = cursor_read_u32le(cursor);
    return a | (b << 32);
}

uint_least8_t cursor_peek_u8(struct cursor *cursor, size_t offset)
{
    assert(offset < cursor->cap_len);
    SLOG(LOG_DEBUG, "Peeking byte 0x%x, %zu left, %zu offset", *(cursor->head + offset),
            cursor->cap_len, offset);
    return *(cursor->head + offset);
}

uint_least16_t cursor_peek_u16n(struct cursor *cursor, size_t offset)
{
    uint_least32_t a = cursor_peek_u8(cursor, offset);
    uint_least32_t b = cursor_peek_u8(cursor, offset + 1);
    return (a << 8) | b;
}

uint_least16_t cursor_peek_u16le(struct cursor *cursor, size_t offset)
{
    uint_least32_t a = cursor_peek_u8(cursor, offset);
    uint_least32_t b = cursor_peek_u8(cursor, offset + 1);
    return a | (b << 8);
}

uint_least32_t cursor_peek_u24n(struct cursor *cursor, size_t offset)
{
    uint_least32_t a = cursor_peek_u8(cursor, offset);
    uint_least32_t b = cursor_peek_u8(cursor, offset + 1);
    uint_least32_t c = cursor_peek_u8(cursor, offset + 2);
    return (a << 16) | (b << 8) | c;
}

uint_least32_t cursor_peek_u24le(struct cursor *cursor, size_t offset)
{
    uint_least32_t a = cursor_peek_u8(cursor, offset);
    uint_least32_t b = cursor_peek_u8(cursor, offset + 1);
    uint_least32_t c = cursor_peek_u8(cursor, offset + 2);
    return a | (b << 8) | (c << 16);
}

uint_least32_t cursor_peek_u32n(struct cursor *cursor, size_t offset)
{
    uint_least32_t a = cursor_peek_u16n(cursor, offset);
    uint_least32_t b = cursor_peek_u16n(cursor, offset + 2);
    return (a << 16) | b;
}

uint_least32_t cursor_peek_u32le(struct cursor *cursor, size_t offset)
{
    uint_least32_t a = cursor_peek_u16le(cursor, offset);
    uint_least32_t b = cursor_peek_u16le(cursor, offset + 2);
    return a | (b << 16);
}

uint_least64_t cursor_peek_u64n(struct cursor *cursor, size_t offset)
{
    uint_least64_t a = cursor_peek_u32n(cursor, offset);
    uint_least64_t b = cursor_peek_u32n(cursor, offset + 4);
    return (a << 32) | b;
}

uint_least64_t cursor_peek_u64le(struct cursor *cursor, size_t offset)
{
    uint_least64_t a = cursor_peek_u32le(cursor, offset);
    uint_least64_t b = cursor_peek_u32le(cursor, offset + 4);
    return a | (b << 32);
}

enum proto_parse_status cursor_read_fixed_string(struct cursor *cursor, char **out_str, size_t str_len)
{
    SLOG(LOG_DEBUG, "Reading string of size %zu", str_len);
    if (cursor->cap_len < str_len) return PROTO_PARSE_ERR;
    if (!out_str) {
        cursor_drop(cursor, str_len);
        return PROTO_OK;
    }
    char *str = tempstr();
    unsigned copied_len = MIN(str_len, TEMPSTR_SIZE - 1);
    cursor_copy(str, cursor, copied_len);
    str[copied_len] = '\0';
    if (copied_len < str_len) {
        cursor_drop(cursor, str_len - copied_len);
    }
    if(out_str) *out_str = str;
    return PROTO_OK;
}

int cursor_read_string(struct cursor *cursor, char *out_buf, size_t size_buf, size_t max_src)
{
    uint8_t marker[1] = {0x00};
    int str_len = cursor_lookup_marker(cursor, marker, sizeof(marker), max_src);
    SLOG(LOG_DEBUG, "Marker {0x00} found at position %d, searched %zu bytes (cap len %zu)", str_len,
            max_src, cursor->cap_len);
    if (str_len < 0) return -1;
    size_t str_size = str_len + sizeof(marker);
    if (!out_buf) {
        cursor_drop(cursor, str_size);
        return 0;
    }
    assert(size_buf >= 1);
    int copied_bytes = MIN(str_size, size_buf - 1);
    cursor_copy(out_buf, cursor, copied_bytes);
    if (size_buf - 1 < str_size) {
        cursor_drop(cursor, str_size - size_buf);
        out_buf[copied_bytes] = '\0';
    }
    SLOG(LOG_DEBUG, "Read a null terminated string %s of size %zu", out_buf, str_size);
    return str_size;
}

int cursor_read_utf16(struct cursor *cursor, iconv_t cd, char *out_buf, size_t buf_size, size_t max_src)
{
    char marker[2] = {0x00, 0x00};
    int str_len = cursor_lookup_marker(cursor, marker, sizeof(marker), max_src);
    SLOG(LOG_DEBUG, "Marker {0x00, 0x00} found at position %d, searched %zu bytes (cap len %zu)", str_len,
            max_src, cursor->cap_len);
    if (str_len < 0) return -1;
    uint8_t const *src = cursor->head;
    size_t str_size = str_len + sizeof(marker);
    if (str_size ^ 2) str_size++;
    if (!out_buf) {
        cursor_drop(cursor, str_size);
        return 0;
    }
    size_t to_drop = str_size;
    SLOG(LOG_DEBUG, "Reading and converting %zu bytes", str_size);
    iconv(cd, (char **)&src, &str_size, &out_buf, &buf_size);
    cursor_drop(cursor, to_drop);
    return to_drop;
}

int cursor_lookup_marker(struct cursor *cursor, const void *marker, size_t marker_len, size_t max_src)
{
    uint8_t *new_head = memmem(cursor->head, MIN(cursor->cap_len, max_src), marker, marker_len);
    if (!new_head) return -1;
    int gap_size = new_head - cursor->head;
    return gap_size;
}

int cursor_drop_until(struct cursor *cursor, const void *marker, size_t marker_len, size_t max_src)
{
    int dropped_bytes = cursor_lookup_marker(cursor, marker, marker_len, max_src);
    if (dropped_bytes < 0) return -1;
    cursor_drop(cursor, dropped_bytes);
    return dropped_bytes;
}

int cursor_drop_string(struct cursor *cursor, size_t max_src)
{
    return cursor_read_string(cursor, NULL, 0, max_src);
}

int cursor_drop_utf16(struct cursor *cursor, size_t max_src)
{
    return cursor_read_utf16(cursor, NULL, NULL, 0, max_src);
}

void cursor_copy(void *dst, struct cursor *cursor, size_t n)
{
    SLOG(LOG_DEBUG, "Copying %zu bytes", n);
    assert(cursor->cap_len >= n);
    memcpy(dst, cursor->head, n);
    cursor->head += n;
    cursor->cap_len -= n;
}

void cursor_drop(struct cursor *cursor, size_t n)
{
    SLOG(LOG_DEBUG, "Skipping %zu bytes", n);
    assert(cursor->cap_len >= n);
    cursor->cap_len -= n;
    cursor->head += n;
}

bool cursor_is_empty(struct cursor const *cursor)
{
    return cursor->cap_len == 0;
}

enum proto_parse_status cursor_read_fixed_int_n(struct cursor *cursor, uint_least64_t *out_res, unsigned len)
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

enum proto_parse_status cursor_read_fixed_int_le(struct cursor *cursor, uint_least64_t *out_res, unsigned len)
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

