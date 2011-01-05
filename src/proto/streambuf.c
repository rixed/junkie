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
#include <junkie/tools/log.h>
#include <junkie/tools/mallocer.h>
#include <junkie/proto/streambuf.h>

static char const Id[] = "$Id$";

/*
 * Construction
 */

int streambuf_ctor(struct streambuf *sbuf, parse_fun *parse, size_t max_size)
{
    SLOG(LOG_DEBUG, "Constructing a streambuf@%p of max size %zu", sbuf, max_size);

    sbuf->parse = parse;
    sbuf->max_size = max_size;
    for (unsigned d = 0; d < 2; d++) {
        sbuf->dir[d].buffer_size = 0;
        sbuf->dir[d].buffer = NULL;
        sbuf->dir[d].restart_offset = 0;
    }

    return 0;
}

void streambuf_dtor(struct streambuf *sbuf)
{
    SLOG(LOG_DEBUG, "Destructing the streambuf@%p", sbuf);

    for (unsigned d = 0; d < 2; d++) {
        if (sbuf->dir[d].buffer) {
            FREE(sbuf->dir[d].buffer);
            sbuf->dir[d].buffer = NULL;
        }
    }
}

void streambuf_set_restart(struct streambuf *sbuf, unsigned way, uint8_t const *p)
{
    assert(way < 2);
    assert(sbuf->dir[way].buffer);
    size_t offset = p - sbuf->dir[way].buffer;
    assert(offset <= sbuf->dir[way].buffer_size);

    SLOG(LOG_DEBUG, "Setting restart offset of streambuf@%p to %zu", sbuf, offset);
    sbuf->dir[way].restart_offset = offset;
}

static enum proto_parse_status streambuf_append(struct streambuf *sbuf, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len)
{
    assert(way < 2);
    SLOG(LOG_DEBUG, "Append %zu bytes (%zu on wire) to streambuf@%p of size %zu (%zu kept)",
        cap_len, wire_len, sbuf, sbuf->dir[way].buffer_size, sbuf->dir[way].buffer_size-sbuf->dir[way].restart_offset);
    // Naive implementation : each time we add some bytes we realloc buffer
    MALLOCER(streambufs);

    if (wire_len > cap_len) return PROTO_TOO_SHORT; // as soon as we want a streambuf we want all bytes

    size_t const keep_size = sbuf->dir[way].buffer_size - sbuf->dir[way].restart_offset;
    size_t const new_size = keep_size + cap_len;
    if (new_size > sbuf->max_size) return PROTO_PARSE_ERR;

    uint8_t *new_buffer = MALLOC(streambufs, new_size);
    if (! new_buffer) return PROTO_PARSE_ERR;

    // Assemble kept buffer and new payload
    if (sbuf->dir[way].buffer) {
        memcpy(new_buffer, sbuf->dir[way].buffer + sbuf->dir[way].restart_offset, keep_size);
        FREE(sbuf->dir[way].buffer);
    }
    memcpy(new_buffer + keep_size, packet, cap_len);

    sbuf->dir[way].buffer = new_buffer;
    sbuf->dir[way].buffer_size = new_size;
    sbuf->dir[way].restart_offset = 0;

    return PROTO_OK;
}

// FIXME: This is stupid to buffer the first packet since many times the parse will not require buffering.
//        So add a flag 'buffer_is_malloced' if it's malloced (false when buffer points to the packet directly),
//        and handle it accordingly when sbuf->parse returns OK with a restart_offset < buffer_size.
enum proto_parse_status streambuf_add(struct streambuf *sbuf, struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn)
{
    assert(way < 2);
    enum proto_parse_status status = streambuf_append(sbuf, way, packet, cap_len, wire_len);
    if (status != PROTO_OK) return status;

    if (sbuf->dir[way].restart_offset == sbuf->dir[way].buffer_size) {    // emptiness is not interresting
        return proto_parse(NULL, parent, way, packet, cap_len, wire_len, now, okfn);
    }

    assert(sbuf->dir[way].buffer_size >= sbuf->dir[way].restart_offset);
    size_t const len = sbuf->dir[way].buffer_size - sbuf->dir[way].restart_offset;
    assert(sbuf->dir[way].buffer);

    // If the user do not call streambuf_restart_offset() then this means there is no restart
    size_t const offset = sbuf->dir[way].restart_offset;
    sbuf->dir[way].restart_offset = sbuf->dir[way].buffer_size;
    return sbuf->parse(parser, parent, way, sbuf->dir[way].buffer + offset, len, len, now, okfn);
}

