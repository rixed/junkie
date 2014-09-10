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
#include <ctype.h>
#include "junkie/cpp.h"
#include "junkie/tools/log.h"
#include "junkie/tools/miscmacs.h"
#include "junkie/proto/proto.h"
#include "junkie/proto/http.h"
#include "httper.h"

#undef LOG_CAT
#define LOG_CAT proto_http_log_category

/*
 * Parse Command
 *
 * Note: The field callback function receives the raw field value,
 * possibly including newlines if it was on multiple line.
 *
 * FIXME: Add a copy_token_striped function to pass a stripped value
 * to the callback function.
 */

enum proto_parse_status httper_parse(struct httper const *httper, size_t *head_sz, uint8_t const *packet,
        size_t packet_len, void *user_data, size_t *expected_bytes)
{
    struct liner liner, tokenizer;
    bool found = false;

    for (unsigned c = 0; c < httper->nb_commands; c++) {
        struct httper_command const *const cmd = httper->commands + c;

        // Start by looking for the command before tokenizing (tokenizing takes too much time on random traffic)
        if (0 != strncmp(cmd->name, (char const *)packet, MIN(packet_len, cmd->len))) continue;
        if (packet_len < cmd->len) {
            if (expected_bytes) *expected_bytes = cmd->len;
            return PROTO_TOO_SHORT;
        }

        liner_init(&liner, &delim_lines, (char const *)packet, packet_len);
        liner_init(&tokenizer, &delim_blanks, liner.start, liner_tok_length(&liner));

        if (liner_tok_length(&tokenizer) != cmd->len) {
no_command:
            SLOG(LOG_DEBUG, "Cannot find command");
            return PROTO_PARSE_ERR;
        }
        SLOG(LOG_DEBUG, "Found command %s", cmd->name);
        liner_next(&tokenizer);
        int ret = cmd->cb(c, &tokenizer, user_data);
        if (ret) return PROTO_PARSE_ERR;

        found = true;
        break;
    }

    if (! found) goto no_command;

    // Parse header fields
    unsigned nb_hdr_lines = 0;

    int field_idx = -1;
    char const *field_end = NULL;

    while (true) {
        // Next line
        bool const has_newline = liner.delim_size > 0;
        liner_next(&liner);
        if (liner_eof(&liner)) {
            // As an accommodation to old HTTP implementations, we allow a single line command
            // FIXME: check line termination with "*/x.y" ?
            if (nb_hdr_lines == 0 && has_newline) break;
            if (expected_bytes) *expected_bytes = 1;
            return PROTO_TOO_SHORT;
        }

        // If empty line we reached the end of the headers
        if (liner_tok_length(&liner) == 0) break;

        // Check if we reached the end of a multiline field.
        // FIXME: Is isspace appropriate here?
        if (! isspace(liner.start[0])) {
            if (field_idx >= 0) {
                liner_grow(&tokenizer, field_end);
                // Absorb all remaining of line onto this token
                liner_expand(&tokenizer);
                int ret = httper->fields[field_idx].cb(field_idx, &tokenizer, user_data);
                if (ret) return PROTO_PARSE_ERR;
            }

            // Tokenize the header line
            liner_init(&tokenizer, &delim_colons, liner.start, liner_tok_length(&liner));

            field_idx = -1;
            for (unsigned f = 0; f < httper->nb_fields; f++) {
                struct httper_field const *field = httper->fields + f;

                if (liner_tok_length(&tokenizer) < field->len) continue;
                if (0 != strncasecmp(field->name, tokenizer.start, liner_tok_length(&tokenizer))) continue;

                SLOG(LOG_DEBUG, "Found field %s", field->name);
                liner_next(&tokenizer);
                field_idx = f;
                break;
            }
        }
        field_end = liner.start + liner.tok_size;   // save end of line position in field_end
        nb_hdr_lines ++;
    }

    if (field_idx >= 0) {
        liner_grow(&tokenizer, field_end);
        // Absorb all remaining of line onto this token
        liner_expand(&tokenizer);
        int ret = httper->fields[field_idx].cb(field_idx, &tokenizer, user_data);
        if (ret) return PROTO_PARSE_ERR;
    }

    if (head_sz) *head_sz = liner_parsed(&liner);
    return PROTO_OK;
}

