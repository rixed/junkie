// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef BER_H_130502
#define BER_H_130502
#include <junkie/proto/proto.h>
#include <junkie/proto/cursor.h>

/** @file
 * @brief helper to parse BER/DER encoded payloads
 *
 * You can decode encoded primitive values, enter or skip constructed values.
 */

struct ber_time {
    uint16_t year;
    uint8_t month, day, hour, min, sec;
};

char const *ber_time_2_str(struct ber_time const *);
int cmp_ber_time(struct ber_time const *t1, struct ber_time const *t2);

/// Fill in a struct utc_time with the value pointed that must be either
/// an UTCTime or a GeneralizedTime
enum proto_parse_status ber_extract_time(struct cursor *, struct ber_time *);

struct ber_uint {
    uint8_t num[20];
    uint8_t len;
};

enum proto_parse_status ber_extract_uint(struct cursor *, struct ber_uint *);

char const *ber_uint_2_str(struct ber_uint const *);

/// Skip next value
enum proto_parse_status ber_skip(struct cursor *);

/// Copy the next value
enum proto_parse_status ber_copy(struct cursor *, void *dest, size_t *nb_bytes, size_t max_sz);

/// Skip an explicitly tagged value if present at cursor
enum proto_parse_status ber_skip_optional(struct cursor *, unsigned tag);

/// Enter a sequence or set
/** @note that you must then parse is fully or pop out by restoring your previous cursor and then ber_skip it.
 */
enum proto_parse_status ber_enter(struct cursor *);

typedef enum proto_parse_status foreach_fn(struct cursor *, void *);
/// Call a user function for each value of a SET OF/SEQUENCE OF
enum proto_parse_status ber_foreach(struct cursor *, foreach_fn *, void *);

/// Extract a string (of some sort) at cursor
enum proto_parse_status ber_decode_string(struct cursor *, size_t out_sz, char *out);

#endif
