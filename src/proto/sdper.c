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
#include <string.h>
#include "junkie/cpp.h"
#include "junkie/tools/log.h"
#include "junkie/tools/miscmacs.h"
#include "sdper.h"
#include "junkie/proto/proto.h"

static char const Id[] = "$Id: 8fbc788693f564da101ece006ce1761b2aa70e8a $";

#undef LOG_CAT
#define LOG_CAT proto_log_category

/*
 * Parse Command
 */

int sdper_parse(struct sdper const *sdper, size_t *head_sz, uint8_t const *packet, size_t packet_len, void *user_data)
{
    // REVIEW: eols and spcs should be provided by liner.
    struct liner_delimiter
        eols[] = { { "\r\n", 2 }, { "\n", 1 } },
        cols[] = { { "= ", 2}, { "=", 1 } };
    struct liner_delimiter_set const
        lines =  { NB_ELEMS(eols), eols, false },
        eq = { NB_ELEMS(cols), cols, true };

    struct liner liner, tokenizer;

    liner_init(&liner, &lines, (char const *)packet, packet_len);

    // Parse header fields
    while (true) {
        // Next line
        if (liner_eof(&liner)) break;

        // Otherwise tokenize the header line
        liner_init(&tokenizer, &eq, liner.start, liner_tok_length(&liner));

        for (unsigned f = 0; f < sdper->nb_fields; f++) {
            struct sdper_field const *field = sdper->fields + f;

            size_t len = liner_tok_length(&tokenizer);
            if (len != field->length)
              continue;

            if (0 != strncasecmp(field->name, tokenizer.start, len)) continue;

            SLOG(LOG_DEBUG, "Found field %s", field->name);
            liner_next(&tokenizer);
            int ret = field->cb(f, &tokenizer, user_data);
            if (ret) return ret;
            break;
        }

        liner_next(&liner);
    }

    if (head_sz) *head_sz = liner_parsed(&liner);
    return 0;
}

