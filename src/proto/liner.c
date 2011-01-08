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
#include <junkie/tools/miscmacs.h>
#include <junkie/proto/proto.h>
#include "proto/liner.h"

static char const Id[] = "$Id: b9348a21349c6b6101f8818e0f9ba93cfd31251e $";

#undef LOG_CAT
#define LOG_CAT proto_log_category

/*
 * Tools
 */

void copy_token(char *dest, size_t dest_sz, struct liner *liner)
{
    size_t len = MIN(dest_sz-1, liner_tok_length(liner));
    memcpy(dest, liner->start, len);
    dest[len] = '\0';
}

static void liner_skip(struct liner *liner, size_t len)
{
    assert(liner->rem_size >= len);
    liner->start += len;
    liner->rem_size -= len;
}

unsigned long long liner_strtoull(struct liner *liner, char const **end, int base)
{
    assert(base > 1);
    unsigned long long ret = 0;

    unsigned o;
    for (o = 0; o < liner->tok_size; o++) {
        char c = liner->start[o];
        unsigned digit = 0;
        if (c >= '0' && c <= (base < 10 ? '0'+base-1 : '9')) {
            digit = c - '0';
        } else if (base > 10 && c >= 'a' && c <= 'a' + (base-10)) {
            digit = c - 'a';
        } else if (base > 10 && c >= 'A' && c <= 'A' + (base-10)) {
            digit = c - 'A';
        } else {
            break;
        }
        ret = ret * base + digit;
    }
    if (end) *end = liner->start + o;

    return ret;
}

/*
 * Parse
 */

static int look_for_delim(size_t *tok_len, size_t *delim_len, char const *start, size_t rem_size, struct liner_delimiter_set const *delims)
{
    struct {
        unsigned matched;  // how many chars were already matched
        bool winner;
        size_t tok_len;
    } matches[delims->nb_delims];

    for (unsigned d = 0; d < NB_ELEMS(matches); d++) {
        matches[d].matched = 0;
        matches[d].winner = false;
        assert(delims->delims[d].len > 0);  // or the following algo will fail
    }

    int best_winner = -1;
    unsigned nb_matching = 0;

    // Now scan the buffer until a match
    for (unsigned o = 0; o < rem_size; o++) {
        char const c = start[o];
        if (best_winner != -1 && nb_matching == 0) break; // nothing left matching

        for (unsigned d = 0; d < delims->nb_delims; d++) {
            struct liner_delimiter const *delim = delims->delims+d;
            if (! matches[d].winner) {
                if (c == delim->str[matches[d].matched]) {
                    nb_matching += matches[d].matched == 0;
                    if (++matches[d].matched >= delim->len) {   // we have a winner
                        matches[d].winner = true;  // but keep looking for a longer match
                        matches[d].tok_len = o - matches[d].matched + 1;
                        if (-1 == best_winner || matches[d].matched > matches[best_winner].matched) {
                            best_winner = d;
                        }
                        nb_matching --;
                    }
                } else if (matches[d].matched > 0) {
                    matches[d].matched = c == delim->str[0];
                    nb_matching -= matches[d].matched == 0;
                }
            }
        }
    }

    if (-1 == best_winner) return -1;

    *tok_len   = matches[best_winner].tok_len;
    *delim_len = matches[best_winner].matched;

    return 0;
}

// If we have another delimiter just after the delimiter, make it part of the delimiter
static void liner_skip_delimiters(struct liner *liner)
{
    if (! liner->delims->collapse) return;
    
    size_t const rem = liner->rem_size - liner->tok_size - liner->delim_size;
    char const *const after = liner->start + liner->tok_size + liner->delim_size;

    for (unsigned d = 0; d < liner->delims->nb_delims; d++) {
        struct liner_delimiter const *const delim = liner->delims->delims+d;
        if (delim->len > rem) continue;
        if (0 != strncmp(after, delim->str, delim->len)) continue;
        liner->delim_size += delim->len;
        SLOG(LOG_DEBUG, "absorbing one more delimiter (delim len now %zu)", liner->delim_size);
        liner_skip_delimiters(liner);
        break;
    }
}

void liner_next(struct liner *liner)
{
    // Skip previously found token
    liner_skip(liner, liner->tok_size + liner->delim_size);

    // And look for new one
    if (0 != look_for_delim(&liner->tok_size, &liner->delim_size, liner->start, liner->rem_size, liner->delims)) {
        // then all remaining bytes are the next token
        liner->tok_size = liner->rem_size;
        liner->delim_size = 0;
    }

    liner_skip_delimiters(liner);
}

/*
 * Construction/Destruction
 */

void liner_init(struct liner *liner, struct liner_delimiter_set const *delims, char const *buffer, size_t buffer_size)
{
    liner->start = buffer;
    liner->tok_size = liner->delim_size = 0;
    liner->tot_size = liner->rem_size = buffer_size;
    liner->delims = delims;

    // Get first line
    liner_next(liner);
}

extern inline bool liner_eof(struct liner *);
extern inline size_t liner_tok_length(struct liner *);
extern inline size_t liner_rem_length(struct liner *);
extern inline size_t liner_parsed(struct liner *);
extern inline void liner_expand(struct liner *liner);

static struct liner_delimiter
    eols[]     = { { "\r\n", 2 }, { "\n", 1 } },
    blanks[]   = { { " ", 1 }, { "\r\n", 2 }, { "\n", 1 } },
    spaces[]   = { { " ", 1 } },
    colons[]   = { { ": ", 2 }, { ":", 1 } },
    semicols[] = { { "; ", 2 }, { ";", 1 } };
struct liner_delimiter_set const
    delim_lines      = { NB_ELEMS(eols), eols, false },
    delim_blanks     = { NB_ELEMS(blanks), blanks, true },
    delim_spaces     = { NB_ELEMS(spaces), spaces, true },
    delim_colons     = { NB_ELEMS(colons), colons, true },
    delim_semicolons = { NB_ELEMS(semicols), semicols, true };

