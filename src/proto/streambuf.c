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
#include <assert.h>
#include "junkie/tools/log.h"
#include "junkie/tools/objalloc.h"
#include "junkie/proto/streambuf.h"

#undef LOG_CAT
#define LOG_CAT streambuf_log_category

LOG_CATEGORY_DEF(streambuf);

/*
 * Pool of mutexes
 */

static struct mutex_pool streambuf_locks;

/*
 * Construction
 */

int streambuf_ctor(struct streambuf *sbuf, parse_fun *parse, size_t max_size, struct mutex_pool *pool)
{
    SLOG(LOG_DEBUG, "Constructing a streambuf@%p of max size %zu", sbuf, max_size);

    sbuf->parse = parse;
    sbuf->max_size = max_size;
    sbuf->mutex = mutex_pool_anyone(pool ? pool : &streambuf_locks);

    for (unsigned d = 0; d < 2; d++) {
        sbuf->dir[d].buffer = NULL;
        sbuf->dir[d].cap_len = 0;
        sbuf->dir[d].wire_len = 0;
        sbuf->dir[d].restart_offset = 0;
        sbuf->dir[d].wait_offset = 0;
        sbuf->dir[d].buffer_is_malloced = 0;
        timeval_reset(&sbuf->dir[d].last_received_tv);
    }

    return 0;
}

void streambuf_dtor(struct streambuf *sbuf)
{
    SLOG(LOG_DEBUG, "Destructing the streambuf@%p", sbuf);

    for (unsigned d = 0; d < 2; d++) {
        if (sbuf->dir[d].buffer) {
            if (sbuf->dir[d].buffer_is_malloced) objfree((void*)sbuf->dir[d].buffer);
            sbuf->dir[d].buffer = NULL;
        }
    }
}

static const char *streambuf_2_str(struct streambuf *sbuf, unsigned way)
{
    return tempstr_printf("streambuf@%p[%u], buffer size %zu, wire_len %zu, restart_offset %zu, wait_offset %zu, is_malloced %d",
            sbuf, way, sbuf->dir[way].cap_len, sbuf->dir[way].wire_len, sbuf->dir[way].restart_offset,
            sbuf->dir[way].wait_offset, sbuf->dir[way].buffer_is_malloced);
}

void streambuf_set_restart(struct streambuf *sbuf, unsigned way, uint8_t const *p, size_t wait_offset)
{
    assert(way < 2);

    size_t const offset = p - sbuf->dir[way].buffer;

    /* If we ask to restart at some offset, then obviously we must have a buffer.
     * The only exception is when we want to restart at NULL - this is useful because
     * parsers receive NULL instead of packet data when we want to signal a gap
     * (see commit ffbcb909200c62861f38ff8516dcad2bf5693bfb), and we do not want
     * to force them to check whether packet is set or not to restart it from the
     * start (note: restarting at a gap will force the parse to be terminated by
     * streambuf if not the parser itself).
     */
    if (p) {
        assert(sbuf->dir[way].buffer);
        assert(p >= sbuf->dir[way].buffer);
    }

    SLOG(LOG_DEBUG, "Setting restart offset to %zu, waiting offset to %zu for %s", offset, wait_offset,
            streambuf_2_str(sbuf, way));
    sbuf->dir[way].restart_offset = offset;
    sbuf->dir[way].wait_offset = wait_offset;
}

static void streambuf_empty(struct streambuf_unidir *dir)
{
    if (dir->buffer) {
        if (dir->buffer_is_malloced) objfree((void*)dir->buffer);
        dir->buffer = NULL;
        dir->cap_len = 0;
        dir->wire_len = 0;
        dir->buffer_is_malloced = 0;
    } else {
        assert(0 == dir->cap_len);
    }
}

static enum proto_parse_status streambuf_shrink(struct streambuf *sbuf, unsigned way, uint8_t const *packet,
        size_t cap_len, size_t wire_len)
{
    struct streambuf_unidir *dir = sbuf->dir+way;
    if ( dir->restart_offset > (dir->wire_len - wire_len) && dir->restart_offset < dir->wire_len ) {
        size_t num_bytes = dir->wire_len - dir->restart_offset;
        size_t pkt_offset = wire_len - num_bytes;
        SLOG(LOG_DEBUG, "Num bytes %zu, pkt offset %zu", num_bytes, pkt_offset);
        if (pkt_offset > cap_len) {
            SLOG(LOG_DEBUG, "Shrink in a middle of uncaptured bytes");
            return PROTO_TOO_SHORT;
        }
        size_t uncap_bytes = wire_len - cap_len;
        size_t copied_bytes = MIN(sbuf->max_size, num_bytes - uncap_bytes);
        uint8_t *new_buffer = objalloc_nice(copied_bytes, "streambufs");
        memcpy(new_buffer, packet + pkt_offset, copied_bytes);
        if (dir->buffer_is_malloced) objfree((void*)dir->buffer);
        dir->buffer = new_buffer;
        dir->cap_len = copied_bytes;
        dir->buffer_is_malloced = true;
        dir->restart_offset = 0;
        dir->wire_len = wire_len - pkt_offset;
        return PROTO_OK;
    }
    // No need to shrink, it will be handle on next append
    return PROTO_OK;
}

static enum proto_parse_status streambuf_append(struct streambuf *sbuf, unsigned way, uint8_t const *packet,
        size_t cap_len, size_t wire_len, struct timeval const *now)
{
    assert(way < 2);
    SLOG(LOG_DEBUG, "Append %zu bytes (%zu captured) to %s", wire_len, cap_len, streambuf_2_str(sbuf, way));
    // Naive implementation : each time we add some bytes we realloc buffer
    // FIXME: use a redim_array ?
    // FIXME: better yet, rewrite everything using pkt-lists from end to end

    struct streambuf_unidir *dir = sbuf->dir+way;
    if (cap_len > 0) {
        SLOG(LOG_DEBUG, "Set last_received_tv to %s", timeval_2_str(now));
        dir->last_received_tv = *now;
    }

    if (! dir->buffer) {
        SLOG(LOG_DEBUG, "Initializing new streambuffer using packet on stack");
        dir->buffer = packet;
        dir->cap_len = cap_len;
        dir->wire_len = wire_len;
        dir->buffer_is_malloced = false;
        return PROTO_OK;
    }

    ssize_t const new_wire_len = dir->wire_len - dir->restart_offset + wire_len;
    if (dir->restart_offset == 0 && (dir->cap_len == sbuf->max_size || dir->wire_len > dir->cap_len)) {
        SLOG(LOG_DEBUG, "Streambuf full or streambuf with gap, , updating wire_len from %zu to %zu", dir->wire_len, new_wire_len);
        dir->wire_len = new_wire_len;
        return PROTO_OK;
    }

    size_t const keep_size = (dir->cap_len > dir->restart_offset) ? dir->cap_len - dir->restart_offset : 0;
    size_t const size_append = MIN(cap_len, sbuf->max_size - keep_size);
    bool const keep_initial_buffer = keep_size > 0;
    bool const append_pkt = dir->wire_len - dir->restart_offset < sbuf->max_size;

    ssize_t new_size = 0;
    if (append_pkt) new_size += size_append;
    if (keep_initial_buffer) new_size += keep_size;

    SLOG(LOG_DEBUG, "Buffer keep size %zu, size_append %zu, keep initial %d, append pkt %d, new_size %zu, new_wire_len %zu",
            keep_size, size_append, keep_initial_buffer, append_pkt, new_size, new_wire_len);
    if (new_size > 0) {
        uint8_t *new_buffer = objalloc_nice(new_size, "streambufs");
        if (! new_buffer) return PROTO_PARSE_ERR;
        if (keep_initial_buffer) {
            SLOG(LOG_DEBUG, "Assemble kept buffer (%zu bytes) and new payload", keep_size);
            memcpy(new_buffer, dir->buffer + dir->restart_offset, keep_size);
        }
        if (append_pkt) {
            ssize_t const max_copied_cap_len = MIN(sbuf->max_size - keep_size, cap_len);
            memcpy(new_buffer + keep_size, packet, max_copied_cap_len);
        }
        assert(dir->buffer);
        if (dir->buffer_is_malloced) objfree((void*)dir->buffer);
        dir->buffer = new_buffer;
        dir->cap_len = new_size;
        dir->buffer_is_malloced = true;
        dir->restart_offset = 0;
        dir->wire_len = new_wire_len;
    } else {
        ssize_t const new_restart_offset = dir->restart_offset - (dir->wire_len + wire_len);
        SLOG(LOG_DEBUG, "Buffer restart after captured bytes or in a middle of a gap (restart at %zu, buf wire len %zu, pkt wire len %zu)",
                dir->restart_offset, dir->wire_len, wire_len);
        // check we don't want to restart within uncaptured bytes
        // It can happens when stream buf was truncated
        //               Restart offset v     (dir->wire_len + wire_len) v
        // ----------------------------------------------------------------
        // |XXXXXXXXXXXXXXXXXXXOOOOOOOOOOOOOOOOOOOOOOOOOOXXXXXXXXXXXXXXXX|
        // ----------------------------------------------------------------
        //   dir->capture_len ^           dir->wire_len ^
        //
        // Or when appended packet is a gap
        //            cap_len v     (dir->wire_len + wire_len) v
        // -----------------------------------------------------
        // |XXXXXXXXXXXXXXXXXXXOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO|
        // -----------------------------------------------------
        //   dir->capture_len ^         ^ restart offset
        //      dir->wire_len ^
        if (new_restart_offset < 0) return PROTO_TOO_SHORT;
        dir->restart_offset = new_restart_offset;
        dir->wire_len = new_wire_len;
        streambuf_empty(dir);
    }

    return PROTO_OK;
}

// Copy the packet into a buffer for later use
static int streambuf_keep(struct streambuf *sbuf, unsigned way)
{
    struct streambuf_unidir *dir = sbuf->dir+way;

    if (! dir->buffer) return 0;
    if (dir->buffer_is_malloced) return 0;  // we already own a copy, do not touch it.

    size_t const keep = MIN(dir->cap_len > dir->restart_offset ? dir->cap_len - dir->restart_offset : 0,
            sbuf->max_size);
    SLOG(LOG_DEBUG, "Keeping only %zu bytes of streambuf_unidir@%p", keep, dir);

    if (keep > 0) {
        uint8_t *buf = objalloc_nice(keep, "streambufs");
        if (! buf) {
            dir->buffer = NULL; // never escape from here with buffer referencing a non malloced packet
            return -1;
        }
        memcpy(buf, dir->buffer + dir->restart_offset, keep);
        dir->buffer = buf;
        dir->buffer_is_malloced = true;
        dir->cap_len = keep;
        dir->wire_len -= dir->restart_offset;
        dir->restart_offset = 0;
    } else {
        dir->restart_offset -= dir->cap_len;
        streambuf_empty(dir);
    }

    return 0;
}

static bool offset_in_last_packet(struct streambuf_unidir const *dir, size_t wire_len, size_t cap_len)
{
    size_t old_wire_len = dir->wire_len - wire_len;
    bool offset_in_wire = dir->restart_offset >= old_wire_len && (dir->restart_offset + dir->wait_offset) <= dir->wire_len;
    bool offset_in_captured = dir->restart_offset - old_wire_len < cap_len;
    return (dir->restart_offset > 0 && offset_in_wire && offset_in_captured);
}

static bool offset_start_in_last_packet(struct streambuf_unidir const *dir, size_t wire_len, size_t cap_len)
{
    size_t old_wire_len = dir->wire_len - wire_len;
    bool offset_in_wire = dir->restart_offset >= old_wire_len && (dir->restart_offset + dir->wait_offset) > dir->wire_len;
    return (dir->restart_offset > 0 &&
            offset_in_wire &&
            dir->restart_offset - old_wire_len < cap_len);
}

enum proto_parse_status streambuf_add(struct streambuf *sbuf, struct parser *parser, struct proto_info *parent,
        unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now,
        size_t tot_cap_len, uint8_t const *tot_packet)
{
    mutex_lock(sbuf->mutex);

    assert(way < 2);
    struct streambuf_unidir *dir = sbuf->dir+way;

    enum proto_parse_status status = streambuf_append(sbuf, way, packet, cap_len, wire_len, now);
    if (status != PROTO_OK) goto quit;

    if (dir->wire_len < dir->wait_offset) {
        proto_parse(NULL, parent, way, NULL, 0, 0, now, tot_cap_len, tot_packet); // Advertize what we already parsed
        SLOG(LOG_DEBUG, "Need to wait for more bytes on the packet (wire len %zu, wait offset %zu)",
                dir->wire_len, dir->wait_offset);
        if (0 != streambuf_keep(sbuf, way)) status = PROTO_PARSE_ERR;
        goto quit;
    }

    unsigned nb_max_restart = 10;
    while (nb_max_restart--) {
        // We may want to restart in the middle of uncaptured bytes (either because we just added a gap or because or a previous set_restart.
        size_t offset = dir->restart_offset;
        dir->wait_offset = 0;
        if (offset < dir->cap_len) {
            SLOG(LOG_DEBUG, "Restart from the buffer with offset %zu", offset);
        } else if (offset_in_last_packet(dir, wire_len, cap_len)) {
            // Restart is after truncated packet but in the middle of current packet, we can parse
            if (dir->buffer_is_malloced) objfree((void*)dir->buffer);
            offset -= dir->wire_len - wire_len;
            SLOG(LOG_DEBUG, "We restart after %zu of the last packet (cap_len %zu, wire_len %zu) for %s, use packet on stack",
                    offset, cap_len, wire_len, streambuf_2_str(sbuf, way));
            dir->buffer = packet;
            dir->cap_len = cap_len;
            dir->wire_len = wire_len;
            dir->buffer_is_malloced = false;
        } else if (offset < dir->wire_len) { // restart from the uncaptured zone: signal the gap (up to the end of uncaptured zone)
            SLOG(LOG_DEBUG, "restart for %s is set within uncaptured bytes", streambuf_2_str(sbuf, way));
            size_t dir_wire_len = dir->wire_len;
            streambuf_empty(dir);
            dir->wire_len = dir_wire_len - offset;
            offset = 0;
        } else {    // restart from after wire_len: just be patient
            SLOG(LOG_DEBUG, "%s was totally parsed removing %zu from restart offset", streambuf_2_str(sbuf, way), dir->wire_len);
            dir->restart_offset -= dir->wire_len;
            streambuf_empty(dir);
            goto quit;
        }

        struct timeval const *tv = timeval_is_set(&dir->last_received_tv) ? &dir->last_received_tv : now;

        dir->restart_offset = dir->wire_len;
        status = sbuf->parse(
            parser, parent, way,
            dir->buffer + offset,
            dir->cap_len - offset,
            dir->wire_len - offset,
            tv, tot_cap_len, tot_packet);

        assert(dir->restart_offset >= offset);
        SLOG(LOG_DEBUG, "parse returned %s for %s", proto_parse_status_2_str(status), streambuf_2_str(sbuf, way));

        /* 4 cases here:
         * - either the parser failed,
         * - the parser returned too short but restart is set in the current packet (with a buffer full)
         * - or it succeeded and parsed everything, and we can dispose of the buffer,
         * - or restart_offset was set somewhere because the parser expect more data (that may already been there).
         */
        if (status == PROTO_PARSE_ERR) {
            status = PROTO_PARSE_ERR;
            dir->restart_offset -= dir->wire_len;
            goto quit;
        } else if (offset_in_last_packet(dir, cap_len, wire_len)) {
            SLOG(LOG_DEBUG, "Offset in last packet, restarting");
            continue;
        } else if (offset_start_in_last_packet(dir, cap_len, wire_len)) {
            SLOG(LOG_DEBUG, "Restart start in last packet, buffering it");
            status = streambuf_shrink(sbuf, way, packet, cap_len, wire_len);
            goto quit;
        } else if (status == PROTO_OK && dir->wait_offset > 0) {
            SLOG(LOG_DEBUG, "Keeping streambuf since we are waiting for some bytes and exit streambuf");
            if (0 != streambuf_keep(sbuf, way)) status = PROTO_PARSE_ERR;
            goto quit;
        } else if (status == PROTO_TOO_SHORT) {
            status = PROTO_PARSE_ERR;
            dir->restart_offset -= dir->wire_len;
            goto quit;
        }
    }

    // We reach here when we are constantly restarting. Assume the parser is bugged.
    status = PROTO_PARSE_ERR;
quit:
    // FIXME: in this case we should kill only in one direction!
    if (status != PROTO_OK) {
        // We might have another thread with a reference to this streambuf, we can't let it in an
        // incorrect state hopping nobody will use it since it will be deindex.
        SLOG(LOG_DEBUG, "Not exiting on ok status, emptying buffer %s", streambuf_2_str(sbuf, way));
        dir->restart_offset = 0;
        streambuf_empty(dir);
    }
    mutex_unlock(sbuf->mutex);
    return status;
}

/*
 * Init
 */

void streambuf_init(void)
{
    log_category_streambuf_init();
    mutex_init();
    mutex_pool_ctor(&streambuf_locks, "streambuf");
}

void streambuf_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    mutex_pool_dtor(&streambuf_locks);
#   endif
    mutex_fini();
    log_category_streambuf_fini();
}
