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
        sbuf->dir[d].buffer_size = 0;
        sbuf->dir[d].wire_len = 0;
        sbuf->dir[d].restart_offset = 0;
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

void streambuf_set_restart(struct streambuf *sbuf, unsigned way, uint8_t const *p, bool wait)
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

    SLOG(LOG_DEBUG, "Setting restart offset of streambuf@%p[%u] to %zu (while size=%zu, wire_len %zu)", sbuf, way, offset,
            sbuf->dir[way].buffer_size, sbuf->dir[way].wire_len);
    sbuf->dir[way].restart_offset = offset;
    sbuf->dir[way].wait = wait;
}

static void streambuf_empty(struct streambuf_unidir *dir)
{
    if (dir->buffer) {
        if (dir->buffer_is_malloced) objfree((void*)dir->buffer);
        dir->buffer = NULL;
        dir->buffer_size = 0;
        dir->wire_len = 0;
    } else {
        assert(0 == dir->buffer_size);
    }
}

static enum proto_parse_status streambuf_append(struct streambuf *sbuf, unsigned way, uint8_t const *packet,
        size_t cap_len, size_t wire_len)
{
    assert(way < 2);
    SLOG(LOG_DEBUG, "Append %zu bytes (%zu captured) to streambuf@%p[%u] of size %zu, wire_len %zu (restart @ %zu)",
        wire_len, cap_len, sbuf, way, sbuf->dir[way].buffer_size, sbuf->dir[way].wire_len, sbuf->dir[way].restart_offset);
    // Naive implementation : each time we add some bytes we realloc buffer
    // FIXME: use a redim_array ?
    // FIXME: better yet, rewrite everything using pkt-lists from end to end

    struct streambuf_unidir *dir = sbuf->dir+way;

    if (! dir->buffer) {
        SLOG(LOG_DEBUG, "Initializing new streambuffer using packet on stack");
        dir->buffer = packet;
        dir->buffer_size = cap_len;
        dir->wire_len = wire_len;
        dir->buffer_is_malloced = false;
        return PROTO_OK;
    }

    ssize_t const new_wire_len = dir->wire_len - dir->restart_offset + wire_len;
    if (dir->restart_offset == 0 && dir->buffer_size == sbuf->max_size) {
        SLOG(LOG_DEBUG, "Streambuf full, updating wire_len from %zu to %zu", dir->wire_len, new_wire_len);
        dir->wire_len = new_wire_len;
        return PROTO_OK;
    }

    size_t const keep_size = (dir->buffer_size > dir->restart_offset) ? dir->buffer_size - dir->restart_offset : 0;
    size_t const size_append = MIN(cap_len, sbuf->max_size - keep_size);
    bool const keep_initial_buffer = keep_size > 0;
    bool const append_pkt = dir->wire_len - dir->restart_offset < sbuf->max_size;

    ssize_t new_size = 0;
    if (append_pkt) new_size += size_append;
    if (keep_initial_buffer) new_size += keep_size;

    SLOG(LOG_DEBUG, "Buffer keep size %zu, size_append %zu, keep initial %d, append pkt %d, new_size %zu",
            keep_size, size_append, keep_initial_buffer, append_pkt, new_size);
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
        dir->buffer_size = new_size;
        dir->buffer_is_malloced = true;
        dir->restart_offset = 0;
        dir->wire_len = new_wire_len;
    } else {
        ssize_t const new_restart_offset = dir->restart_offset - (dir->wire_len + wire_len);
        SLOG(LOG_DEBUG, "Buffer restart after captured bytes or in a middle of a gap (restart at %zu, buf wire len %zu, pkt wire len %zu)",
                dir->restart_offset, dir->wire_len, wire_len);
        // check we don't want to restart within uncaptured bytes
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

    size_t const keep = MIN(dir->buffer_size > dir->restart_offset ? dir->buffer_size - dir->restart_offset : 0,
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
        dir->buffer_size = keep;
        dir->wire_len -= dir->restart_offset;
        dir->restart_offset = 0;
    } else {
        dir->restart_offset -= dir->buffer_size;
        streambuf_empty(dir);
    }

    return 0;
}

enum proto_parse_status streambuf_add(struct streambuf *sbuf, struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    mutex_lock(sbuf->mutex);

    assert(way < 2);
    enum proto_parse_status status = streambuf_append(sbuf, way, packet, cap_len, wire_len);
    if (status != PROTO_OK) goto quit;

    struct streambuf_unidir *dir = sbuf->dir+way;

    size_t uncap_len = dir->wire_len - dir->buffer_size;
    unsigned nb_max_restart = 10;
    while (nb_max_restart--) {
        // We may want to restart in the middle of uncaptured bytes (either because we just added a gap or because or a previous set_restart.
        size_t offset = dir->restart_offset;
        dir->wait = false;
        if (offset < dir->buffer_size) {    // simple case: we restart from the buffer
        } else if (offset < dir->buffer_size + uncap_len) { // restart from the uncaptured zone: signal the gap (up to the end of uncaptured zone)
            SLOG(LOG_DEBUG, "streambuf@%p[%u] restart is set within uncaptured bytes", sbuf, way);
            uncap_len -= offset - dir->buffer_size;
            streambuf_empty(dir);
            offset = 0;
        } else {    // restart from after wire_len: just be patient
            SLOG(LOG_DEBUG, "streambuf@%p[%u] was totally parsed", sbuf, way);
            dir->restart_offset -= dir->buffer_size + uncap_len;
            streambuf_empty(dir);
            goto quit;
        }

        dir->restart_offset = dir->buffer_size + uncap_len;
        status = sbuf->parse(
            parser, parent, way,
            dir->buffer + offset,
            dir->buffer_size - offset,
            dir->buffer_size - offset + uncap_len,
            now, tot_cap_len, tot_packet);

        assert(dir->restart_offset >= offset);
        SLOG(LOG_DEBUG, "streambuf@%p[%u] parse returned %s", sbuf, way, proto_parse_status_2_str(status));

        /* 3 cases here:
         * - either the parser failed,
         * - or it succeeded and parsed everything, and we can dispose of the buffer,
         * - or restart_offset was set somewhere because the parser expect more data (that may already been there). */
        switch (status) {
            case PROTO_PARSE_ERR:
                goto quit;
            case PROTO_OK:
                if (dir->wait) {
                    if (0 != streambuf_keep(sbuf, way)) status = PROTO_PARSE_ERR;
                    goto quit;
                }
                break;
            case PROTO_TOO_SHORT:
                if (uncap_len > 0) {
                    status = PROTO_PARSE_ERR; // FIXME: in this case we should kill only in one direction!
                    goto quit;
                }
                if (dir->wait) goto quit;
                break;
        }
    }

    // We reach here when we are constantly restarting. Assume the parser is bugged.
    status = PROTO_PARSE_ERR;
quit:
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
