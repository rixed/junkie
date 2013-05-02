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

/// Skip next value
enum proto_parse_status ber_skip(struct cursor *);

/// Skip an explicitely tagged value if present at cursor
enum proto_parse_status ber_skip_optional(struct cursor *, unsigned tag);

/// Enter a sequence or set
/** @note that you mut then parse is fully or pop out by restoring your previous cursor and then ber_skip it.
 */
enum proto_parse_status ber_enter(struct cursor *);

typedef enum proto_parse_status foreach_fn(struct cursor *, void *);
/// Call a user function for each value of a SET OF/SEQUENCE OF
enum proto_parse_status ber_foreach(struct cursor *, foreach_fn *, void *);

/// Extract a string (of some sort) at cursor
enum proto_parse_status ber_decode_string(struct cursor *, size_t out_sz, char *out);

#endif
