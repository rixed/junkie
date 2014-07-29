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

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <junkie/tools/miscmacs.h>
#include "junkie/tools/log.h"
#include "junkie/tools/string.h"
#include "junkie/tools/string_buffer.h"

#define CHECK_BUFFER_TRUNCATED(buffer) do {     \
    if (buffer->truncated) {                    \
        SLOG(LOG_DEBUG, "Buffer is truncated"); \
        return 0;                               \
    }                                           \
} while(0)

char *buffer_get_string(struct string_buffer const *buffer)
{
    assert(buffer->pos <= buffer->size);
    buffer->head[buffer->pos] = '\0';
    assert(rawmemchr(buffer->head, '\0') == (buffer->head + buffer->pos));
    return buffer->head;
}

const char *string_buffer_2_str(struct string_buffer const *buffer)
{
    return tempstr_printf("string buffer @%p, pos %zu, size %zu, %s, head: '%s'",
            buffer->head, buffer->pos, buffer->size, buffer->truncated ? "truncated" : "not truncated",
            buffer_get_string(buffer));
}

void string_buffer_ctor(struct string_buffer *buffer, char *head, size_t size)
{
    assert(size > 0);
    SLOG(LOG_DEBUG, "Building string buffer with @%p, size %zu", head, size);
    buffer->head = head;
    buffer->pos = 0;
    // We keep a byte for '\0'
    buffer->size = size - 1;
    buffer->truncated = false;
    buffer->head[0] = '\0';
}

size_t buffer_append_unicode(struct string_buffer *buffer, iconv_t cd, char const *src, size_t src_len)
{
    if (!buffer) return 0;
    SLOG(LOG_DEBUG, "Appending an unicode str of length %zu to %s", src_len, string_buffer_2_str(buffer));
    CHECK_BUFFER_TRUNCATED(buffer);
    char *output = buffer->head + buffer->pos;
    size_t start_size, output_size;
    start_size = output_size = buffer_left_size(buffer);
    size_t ret = iconv(cd, (char **)&src, &src_len, &output, &output_size);
    if (ret == (size_t) -1) {
        // Can happen if dest buffer is too small or when last multibyte character
        // is truncated
        SLOG(LOG_DEBUG, "Iconv error: %s", strerror(errno));
        buffer->truncated = true;
    }
    size_t written_bytes = start_size - output_size;
    buffer->pos += written_bytes;
    SLOG(LOG_DEBUG, "Converted %zu bytes", written_bytes);
    return written_bytes;
}

size_t buffer_append_stringn(struct string_buffer *buffer, char const *src, size_t src_max)
{
    if (!buffer) return 0;
    SLOG(LOG_DEBUG, "Appending a string of size %zu to %s", src_max, string_buffer_2_str(buffer));
    CHECK_BUFFER_TRUNCATED(buffer);
    size_t left_size = buffer_left_size(buffer);
    size_t src_len = strnlen(src, src_max);
    size_t size = MIN(left_size, src_len);
    memcpy(buffer->head + buffer->pos, src, size);
    if (size != src_len)
        buffer->truncated = true;
    buffer->pos += size;
    return size;
}

size_t buffer_append_string(struct string_buffer *buffer, char const *src)
{
    return buffer_append_stringn(buffer, src, strlen(src));
}

size_t buffer_append_printf(struct string_buffer *buffer, char const *fmt, ...)
{
    if (!buffer) return 0;
    va_list ap;
    va_start(ap, fmt);
    size_t left_size = buffer_left_size(buffer);
    int n = vsnprintf(buffer->head + buffer->pos, left_size + /*include \0*/ 1, fmt, ap);
    va_end(ap);
    if (n < 0) return 0;
    size_t written_bytes = n;
    if (written_bytes >= left_size)
        buffer->truncated = true;
    buffer->pos += MIN(written_bytes, left_size);
    return n;
}

static size_t utf8_num_bytes(unsigned char c)
{
    if (c < 0x80) return 1;
    if (c < 0xe0) return 2;
    if (c < 0xf0) return 3;
    if (c < 0xf8) return 4;
    if (c < 0xfc) return 5;
    if (c < 0xfe) return 6;
    SLOG(LOG_INFO, "Invalid utf8 sequence");
    return 0;
}

static size_t search_utf8_start(struct string_buffer const *buffer, size_t start)
{
    char const *src = buffer->head;
    while (start > 0) {
        uint8_t category = (src[start] & 0xc0);
        // 0xxxxxxx is a single byte char
        if (category < 0x80) break;
        // 11xxxxxx is the first byte of a multi byte char
        if (category == 0xc0) break;
        start--;
    }
    return start;
}

size_t buffer_append_char(struct string_buffer *buffer, char src)
{
    if (!buffer) return 0;
    CHECK_BUFFER_TRUNCATED(buffer);
    size_t left_size = buffer_left_size(buffer);
    if (left_size == 0) {
        SLOG(LOG_DEBUG, "No more space, truncate it");
        buffer->truncated = true;
        return 0;
    }
    buffer->head[buffer->pos++] = src;
    return 1;
}

static char hexdigit(int n)
{
    return "0123456789abcdef"[n];
}

size_t buffer_append_hexstring(struct string_buffer *buffer, char const *src, size_t src_len)
{
    if (!buffer) return 0;
    SLOG(LOG_DEBUG, "Appending an hexadecimal of size %zu to %s", src_len, string_buffer_2_str(buffer));
    CHECK_BUFFER_TRUNCATED(buffer);
    size_t start_size = buffer_left_size(buffer);
    buffer_append_string(buffer, "0x");
    for (unsigned i = 0; i < src_len; ++i) {
        size_t left_size = buffer_left_size(buffer);
        uint8_t c = src[i];
        if (left_size >= 2) {
            buffer->head[buffer->pos++] = hexdigit(c>>4);
            buffer->head[buffer->pos++] = hexdigit(c&15);
        } else {
            buffer->truncated = true;
            break;
        }
    }
    return start_size - buffer_left_size(buffer);
}

void buffer_rollback(struct string_buffer *buffer, size_t size)
{
    if (!buffer) return;
    size = MIN(buffer->pos, size);
    SLOG(LOG_DEBUG, "Rollback buffer of %zu bytes", size);
    buffer->pos -= size;
}

void buffer_rollback_utf8_char(struct string_buffer *buffer, size_t size)
{
    if (!buffer) return;
    size_t truncate_pos = buffer->pos > size? buffer->pos - size : 0;
    truncate_pos = search_utf8_start(buffer, truncate_pos);
    SLOG(LOG_DEBUG, "Rollback of %s of %zu bytes of utf8 char, truncate position found %zu",
            string_buffer_2_str(buffer), size, truncate_pos);
    buffer->pos = truncate_pos;
}

void buffer_rollback_incomplete_utf8_char(struct string_buffer *buffer)
{
    if (!buffer) return;
    if (buffer->pos == 0) return;
    SLOG(LOG_DEBUG, "Rollback of %s of incomplete utf8 char", string_buffer_2_str(buffer));
    size_t start = search_utf8_start(buffer, buffer->pos - 1);
    size_t num_bytes = utf8_num_bytes(buffer->head[start]);
    if (num_bytes == 0) return;
    size_t size_in_buffer = buffer->pos - start;
    if (num_bytes > size_in_buffer) {
        buffer->pos = start;
    }
}

void buffer_append_escape_quotes(struct string_buffer *buffer, char const *src, size_t src_max, char quoted_char, bool normalize)
{
    enum escape_state {
        ESC_IGNORE,  // Ignore following spaces
        ESC_SPACE,   // Add a space before the first non space, except before ), } and ]
        ESC_OTHER    // Undecided
    } state = ESC_IGNORE;
    size_t block_start = 0;
    unsigned cur = 0;
    for (cur = 0; cur < src_max && !buffer->truncated && src[cur] != '\0'; cur++) {
        char c = src[cur];
        // On space, we enter space state if previous char was not an opening char
        if (normalize && isspace(c)) {
            if (state != ESC_IGNORE) {
                state = ESC_SPACE;
            }
            // We write the current block before first space encountered
            if (block_start < cur) buffer_append_stringn(buffer, src + block_start, cur - block_start);
            block_start = cur + 1;
        } else {
            if (state == ESC_SPACE && !(c == ')' || c == '}' || c == ']')) {
                buffer_append_char(buffer, ' ');
            }
            // We escape quote and starts a new block after this quote
            if (c == quoted_char) {
                if (block_start < cur) buffer_append_stringn(buffer, src + block_start, cur - block_start);
                block_start = cur + 1;
                if (buffer_left_size(buffer) >= 2) {
                    char str[2] = {quoted_char, quoted_char};
                    buffer_append_stringn(buffer, str, 2);
                } else {
                    buffer->truncated = true;
                    break;
                }
            }
            if (c == '(' || c == '{' || c == '[') {
                state = ESC_IGNORE;
            } else {
                state = ESC_OTHER;
            }
        }
    }
    if (block_start < cur) buffer_append_stringn(buffer, src + block_start, cur - block_start);
    // Just drop char if we are in the middle of a multi byte character
    if (buffer->pos > 0) {
        buffer_rollback_incomplete_utf8_char(buffer);
    }
}

