// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef STREAMBUF_H_110106
#define STREAMBUF_H_110106
#include <stdlib.h>
#include <inttypes.h>
#include <junkie/proto/proto.h>

/** @file
 * @brief Stream payload buffering
 *
 * Most of the time, parsing packets one by one is enough. This is fast (we do
 * not need to copy payloads from the pcap buffer) and simple (parsers don't
 * have to handle packets boundaries).
 *
 * But some applicative parsers need to parse payload scattered across packet
 * boundaries. This helper is a simple tool to help them.
 *
 * To use it, first construct a streambuf for your parser (which implies that
 * your parser cannot be unique, which is already certainly the case), giving
 * the constructor a callback and a maximum size to buffer (after which a
 * PROTO_PARSE_ERR will automatically occur).
 *
 * Then, in your parse method, just call streambuf_add with your constructed
 * buffer and all the parse parameters, and your callback will be called with
 * the buffer payload. From there, perform the parse and the call to
 * proto_parse as usual, but in addition, when your parser needs more data to
 * continue, leave the streambuf_cursor to where you would like to resume
 * parsing. Next time (provided you returned PROTO_OK) you will be called with
 * more data, starting to this byte.
 */

struct streambuf {
    parse_fun *parse;       ///< The user parse function
    size_t max_size;        ///< The max buffered size
    /// We want actually one buffer for each direction
    struct streambuf_unidir {
        uint8_t const *buffer;      ///< The buffer itself.
        size_t buffer_size;         ///< The size of the buffer. unset if !buffer.
        size_t restart_offset;      ///< The offset where to start parsing from (don't store a pointer to buffer since buffer will be reallocated).
        bool buffer_is_malloced;    ///< True if the buffer was malloced, false if it references the original packet. unset if !buffer.
        bool wait;                  ///< Wait for more data before restarting.
    } dir[2];
};

int streambuf_ctor(struct streambuf *, parse_fun *parse, size_t max_size);
void streambuf_dtor(struct streambuf *);

/// When a parser want to be called later with (part of) current data
/** @param wait wait for reception of more data before restarting */
void streambuf_set_restart(struct streambuf *, unsigned way, uint8_t const *, bool wait);

/// Add the new payload to the buffered payload, then call the parse callback
enum proto_parse_status streambuf_add(struct streambuf *, struct parser *, struct proto_info *, unsigned, uint8_t const *, size_t, size_t, struct timeval const *, proto_okfn_t *, size_t tot_cap_len, uint8_t const *tot_packet);

#endif
