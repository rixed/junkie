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
#include "junkie/tools/mallocer.h"
#include "junkie/proto/streambuf.h"

/*
 * Construction
 */

int streambuf_ctor(struct streambuf *sbuf, parse_fun *parse, size_t max_size)
{
    SLOG(LOG_DEBUG, "Constructing a streambuf@%p of max size %zu", sbuf, max_size);

    sbuf->parse = parse;
    sbuf->max_size = max_size;
    for (unsigned d = 0; d < 2; d++) {
        sbuf->dir[d].buffer = NULL;
        sbuf->dir[d].buffer_size = 0;
        sbuf->dir[d].restart_offset = 0;
    }

    return 0;
}

void streambuf_dtor(struct streambuf *sbuf)
{
    SLOG(LOG_DEBUG, "Destructing the streambuf@%p", sbuf);

    for (unsigned d = 0; d < 2; d++) {
        if (sbuf->dir[d].buffer) {
            if (sbuf->dir[d].buffer_is_malloced) FREE((void*)sbuf->dir[d].buffer);
            sbuf->dir[d].buffer = NULL;
        }
    }
}

void streambuf_set_restart(struct streambuf *sbuf, unsigned way, uint8_t const *p, bool wait)
{
    assert(way < 2);
    assert(sbuf->dir[way].buffer);
    size_t offset = p - sbuf->dir[way].buffer;
    assert(offset <= sbuf->dir[way].buffer_size);

    SLOG(LOG_DEBUG, "Setting restart offset of streambuf@%p to %zu", sbuf, offset);
    sbuf->dir[way].restart_offset = offset;
    sbuf->dir[way].wait = wait;
}

MALLOCER_DEF(streambufs);

static void streambuf_empty(struct streambuf_unidir *dir)
{
    if (dir->buffer) {
        if (dir->buffer_is_malloced) FREE((void*)dir->buffer);
        dir->buffer = NULL;
        dir->buffer_size = 0;
    } else {
        assert(0 == dir->buffer_size);
    }
}

static enum proto_parse_status streambuf_append(struct streambuf *sbuf, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len)
{
    assert(way < 2);
    SLOG(LOG_DEBUG, "Append %zu bytes (%zu on wire) to streambuf@%p of size %zu (%zu kept)",
        cap_len, wire_len, sbuf, sbuf->dir[way].buffer_size, sbuf->dir[way].buffer_size-sbuf->dir[way].restart_offset);
    // Naive implementation : each time we add some bytes we realloc buffer
    // FIXME: use a redim_array ?

    struct streambuf_unidir *dir = sbuf->dir+way;
    assert(!dir->buffer || dir->restart_offset < dir->buffer_size);

    if (! dir->buffer) {
        dir->buffer = packet;
        dir->buffer_size = cap_len;
        dir->buffer_is_malloced = false;
    } else {
        size_t const keep_size = dir->buffer_size - dir->restart_offset;
        size_t const new_size = keep_size + cap_len;

        if (new_size > 0) {
            if (new_size > sbuf->max_size) return PROTO_PARSE_ERR;
            uint8_t *new_buffer = MALLOC(streambufs, new_size);
            if (! new_buffer) return PROTO_PARSE_ERR;

            // Assemble kept buffer and new payload
            memcpy(new_buffer, dir->buffer + dir->restart_offset, keep_size);
            memcpy(new_buffer + keep_size, packet, cap_len);
            assert(dir->buffer);
            if (dir->buffer_is_malloced) FREE((void*)dir->buffer);
            dir->buffer = new_buffer;
            dir->buffer_size = new_size;
            dir->buffer_is_malloced = true;
        } else {
            streambuf_empty(dir);
        }
    }

    dir->restart_offset = 0;
    return PROTO_OK;
}

static int streambuf_keep(struct streambuf_unidir *dir)
{
    assert(dir->buffer);
    if (dir->buffer_is_malloced) return 0;

    size_t const len = dir->buffer_size - dir->restart_offset;
    uint8_t *buf = MALLOC(streambufs, len);
    if (! buf) {
        dir->buffer = NULL; // never escape from here with buffer referencing a non malloced packet
        return -1;
    }
    memcpy(buf, dir->buffer+dir->restart_offset, len);
    dir->buffer = buf;
    dir->buffer_is_malloced = true;
    dir->buffer_size = len;
    dir->restart_offset = 0;

    return 0;
}

enum proto_parse_status streambuf_add(struct streambuf *sbuf, struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    MALLOCER_INIT(streambufs);
    assert(way < 2);
    enum proto_parse_status status = streambuf_append(sbuf, way, packet, cap_len, wire_len);
    if (status != PROTO_OK) return status;

    struct streambuf_unidir *dir = sbuf->dir+way;
    assert(dir->restart_offset == 0);

    unsigned nb_max_restart = 10;
    while (nb_max_restart--) {
        // If the user do not call streambuf_restart_offset() then this means there is no restart
        dir->restart_offset = dir->buffer_size;
        status = sbuf->parse(parser, parent, way, dir->buffer, dir->buffer_size, dir->buffer_size + (wire_len-cap_len), now, tot_cap_len, tot_packet);

        /* 2 cases here: either the user parsed everything, and we can dispose of the buffer.
         * or the user set the restart_offset somewhere and expect more data.
         * In this situation, if we have a hole at the end of the buffer (because wire_len > cap_len)
         * then we are doomed to fail. If we have no hole, or if the user do not want to wait, then it's all good.
         */
        if (status == PROTO_OK && dir->restart_offset != dir->buffer_size) {
            if (dir->wait && wire_len > cap_len) return PROTO_TOO_SHORT;
            // we must keep the buffer
            if (0 != streambuf_keep(dir)) return PROTO_PARSE_ERR;
            if (dir->wait) return PROTO_OK;
        } else {
            // In all other cases, dispose of the buffer
            streambuf_empty(dir);
            return status;
        }
    }

    // We reach here when we are constantly restarting. Assume the parser is bugged.
    return PROTO_PARSE_ERR;
}

