// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef CURSOR_H_100107
#define CURSOR_H_100107
#include <inttypes.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <junkie/proto/proto.h>

/** @file
 * @brief helper for serialized data stream
 */

struct cursor {
    uint8_t const *head;
    size_t cap_len;     // remaining length that can be read
};

inline void cursor_ctor(struct cursor *cursor, uint8_t const *head, size_t cap_len)
{
    cursor->head = head;
    cursor->cap_len = cap_len;
}

/// Go backward n bytes
inline void cursor_rollback(struct cursor *cursor, size_t n)
{
    SLOG(LOG_DEBUG, "Rollback %zu bytes", n);
    cursor->cap_len += n;
    cursor->head -= n;
}

inline uint_least8_t cursor_read_u8(struct cursor *cursor)
{
    assert(cursor->cap_len >= 1);
    cursor->cap_len --;
    SLOG(LOG_DEBUG, "Reading byte 0x%x, %zu left", *cursor->head, cursor->cap_len);
    return *cursor->head++;
}

inline uint_least16_t cursor_read_u16n(struct cursor *cursor)
{
    uint_least32_t a = cursor_read_u8(cursor);
    uint_least32_t b = cursor_read_u8(cursor);
    return (a << 8) | b;
}

inline uint_least16_t cursor_read_u16le(struct cursor *cursor)
{
    uint_least32_t a = cursor_read_u8(cursor);
    uint_least32_t b = cursor_read_u8(cursor);
    return a | (b << 8);
}

inline uint_least32_t cursor_read_u24n(struct cursor *cursor)
{
    uint_least32_t a = cursor_read_u8(cursor);
    uint_least32_t b = cursor_read_u8(cursor);
    uint_least32_t c = cursor_read_u8(cursor);
    return (a << 16) | (b << 8) | c;
}

inline uint_least32_t cursor_read_u24le(struct cursor *cursor)
{
    uint_least32_t a = cursor_read_u8(cursor);
    uint_least32_t b = cursor_read_u8(cursor);
    uint_least32_t c = cursor_read_u8(cursor);
    return a | (b << 8) | (c << 16);
}

inline uint_least32_t cursor_read_u32n(struct cursor *cursor)
{
    uint_least32_t a = cursor_read_u16n(cursor);
    uint_least32_t b = cursor_read_u16n(cursor);
    return (a << 16) | b;
}

inline uint_least32_t cursor_read_u32le(struct cursor *cursor)
{
    uint_least32_t a = cursor_read_u16le(cursor);
    uint_least32_t b = cursor_read_u16le(cursor);
    return a | (b << 16);
}

inline uint_least64_t cursor_read_u64n(struct cursor *cursor)
{
    uint_least64_t a = cursor_read_u32le(cursor);
    uint_least64_t b = cursor_read_u32le(cursor);
    return (a << 32) | b;
}

inline uint_least64_t cursor_read_u64le(struct cursor *cursor)
{
    uint_least64_t a = cursor_read_u32le(cursor);
    uint_least64_t b = cursor_read_u32le(cursor);
    return a | (b << 32);
}

/// Copy from cursor into a buffer
inline void cursor_copy(void *dst, struct cursor *cursor, size_t n)
{
    SLOG(LOG_DEBUG, "Copying %zu bytes", n);
    assert(cursor->cap_len >= n);
    memcpy(dst, cursor->head, n);
    cursor->head += n;
    cursor->cap_len -= n;
}

/// Go forward by n bytes
inline void cursor_drop(struct cursor *cursor, size_t n)
{
    SLOG(LOG_DEBUG, "Skipping %zu bytes", n);
    assert(cursor->cap_len >= n);
    cursor->cap_len -= n;
    cursor->head += n;
}

inline bool cursor_is_empty(struct cursor const *cursor)
{
    return cursor->cap_len == 0;
}

#ifdef WORDS_BIGENDIAN
#   define cursor_read_u16 cursor_read_u16n
#   define cursor_read_u24 cursor_read_u24n
#   define cursor_read_u32 cursor_read_u32n
#   define cursor_read_u64 cursor_read_u64n
#else
#   define cursor_read_u16 cursor_read_u16le
#   define cursor_read_u24 cursor_read_u24le
#   define cursor_read_u32 cursor_read_u32le
#   define cursor_read_u64 cursor_read_u64le
#endif

/// Reads a string if possible
/** @returns a tempstr with the (beginning of the) string.
 * @param max_len the maximum number of bytes to read. If it's reached before the end of string (nul) then
 *                PROTO_TOO_SHORT is returned (and the cursor is rollbacked).
 * @param str will be set to the tempstr.  */
enum proto_parse_status cursor_read_string(struct cursor *, char **str, size_t max_len);

/// Read an integer len bytes width
enum proto_parse_status cursor_read_fix_int_n(struct cursor *cursor, uint_least64_t *res, unsigned len);
enum proto_parse_status cursor_read_fix_int_le(struct cursor *cursor, uint_least64_t *res, unsigned len);

#define CHECK_LEN(cursor, x, rollback) do { \
    if ((cursor)->cap_len  < (x)) { cursor_rollback(cursor, rollback); return PROTO_TOO_SHORT; } \
} while(0)

#endif
