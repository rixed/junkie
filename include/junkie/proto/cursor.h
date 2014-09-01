// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef CURSOR_H_100107
#define CURSOR_H_100107
#include <inttypes.h>
#include <stdbool.h>
#include <junkie/proto/proto.h>
#include <iconv.h>

/** @file
 * @brief helper for serialized data streram
 */

struct cursor {
    uint8_t const *head;
    size_t cap_len;     // remaining length that can be read
};

void cursor_ctor(struct cursor *, uint8_t const *head, size_t cap_len);

void cursor_rollback(struct cursor *, size_t n);
uint_least8_t cursor_read_u8(struct cursor *);
uint_least16_t cursor_read_u16n(struct cursor *);
uint_least16_t cursor_read_u16le(struct cursor *);
uint_least32_t cursor_read_u24n(struct cursor *);
uint_least32_t cursor_read_u24le(struct cursor *);
uint_least32_t cursor_read_u32n(struct cursor *);
uint_least32_t cursor_read_u32le(struct cursor *);
uint_least64_t cursor_read_u64n(struct cursor *);
uint_least64_t cursor_read_u64le(struct cursor *);

uint_least8_t cursor_peek_u8(struct cursor *cursor, size_t offset);
uint_least16_t cursor_peek_u16n(struct cursor *cursor, size_t offset);
uint_least16_t cursor_peek_u16le(struct cursor *cursor, size_t offset);
uint_least32_t cursor_peek_u24n(struct cursor *cursor, size_t offset);
uint_least32_t cursor_peek_u24le(struct cursor *cursor, size_t offset);
uint_least32_t cursor_peek_u32n(struct cursor *cursor, size_t offset);
uint_least32_t cursor_peek_u32le(struct cursor *cursor, size_t offset);
uint_least64_t cursor_peek_u64n(struct cursor *cursor, size_t offset);
uint_least64_t cursor_peek_u64le(struct cursor *cursor, size_t offset);

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

/*
 * Reads a null terminated string if possible
 * @returns a tempstr with the (beginning of the) string.
 * @param max_src the maximum number of bytes to read. If it's reached before the end of string (nul) then
 *                -1 is returned.
 * @param size_buf Available size in out_buf
 * @param out_len Number of bytes written in out_buf
 * @return Number of bytes read from cursor.
 */
int cursor_read_string(struct cursor *, char *out_buf, size_t size_buf, size_t max_src);
int cursor_read_utf16(struct cursor *cursor, iconv_t cd, char *out_buf, size_t buf_size, size_t max_src);
int cursor_read_fixed_utf16(struct cursor *cursor, iconv_t cd, char *out_buf, size_t buf_size, size_t src_len);

/*
 * Reads a specific length string
 * Return -1 if there is not enough bytes in cursor
 */
int cursor_read_fixed_string(struct cursor *cursor, char *out_buf, size_t size_buf, size_t src_len);

enum proto_parse_status cursor_read_fixed_int_n(struct cursor *cursor, uint_least64_t *res, unsigned len);
enum proto_parse_status cursor_read_fixed_int_le(struct cursor *cursor, uint_least64_t *res, unsigned len);

/*
 * Copy from cursor into a buffer
 */
void cursor_copy(void *, struct cursor *, size_t n);

/*
 * Search marker
 * @return -1 if marker has not been found. Otherwise, return the number of bytes until marker.
 */
int cursor_lookup_marker(struct cursor *cursor, const void *marker, size_t marker_len, size_t max_src);

void cursor_drop(struct cursor *, size_t);
/*
 * Drop cursor until marker is reached.
 * @param max_src Maximum of bytes read from cursor
 * @return -1 if marker has not been found. Otherwise, return the number of dropped bytes.
 */
int cursor_drop_until(struct cursor *cursor, const void *marker, size_t marker_len, size_t max_src);
int cursor_drop_string(struct cursor *cursor, size_t max_src);
int cursor_drop_utf16(struct cursor *cursor, size_t max_src);

bool cursor_is_empty(struct cursor const *);

#define CHECK_LEN(cursor, x, rollback) do { \
    if ((cursor)->cap_len  < (x)) { cursor_rollback(cursor, rollback); { \
        SLOG(LOG_DEBUG, "Could not drop %zu bytes (%zu bytes left)", (size_t) x, (cursor)->cap_len); \
        return PROTO_TOO_SHORT; } \
    } \
} while(0)
#define CHECK(n) CHECK_LEN(cursor, n, 0)
#define CHECK_AND_DROP(n) CHECK(n); cursor_drop(cursor, n);

#endif
