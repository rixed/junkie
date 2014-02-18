// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef CURSOR_H_100107
#define CURSOR_H_100107
#include <inttypes.h>
#include <stdbool.h>
#include <junkie/proto/proto.h>

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

enum proto_parse_status cursor_read_fix_int_n(struct cursor *cursor, uint_least64_t *res, unsigned len);
enum proto_parse_status cursor_read_fix_int_le(struct cursor *cursor, uint_least64_t *res, unsigned len);

/// Copy from cursor into a buffer
void cursor_copy(void *, struct cursor *, size_t n);

void cursor_drop(struct cursor *, size_t);

bool cursor_is_empty(struct cursor const *);

#define CHECK_LEN(cursor, x, rollback) do { \
    if ((cursor)->cap_len  < (x)) { cursor_rollback(cursor, rollback); return PROTO_TOO_SHORT; } \
} while(0)

#endif
