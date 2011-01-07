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
#include <stdio.h>
#include <junkie/proto/proto.h>
#include <junkie/cpp.h>

// Default parse continuation :
static void dump_frame_rec(struct proto_info const *info)
{
    if (info->parent) dump_frame_rec(info->parent);
    printf("%s@%p: %s\n", info->parser->proto->name, info->parser, info->parser->proto->ops->info_2_str(info));
}

int parse_callback(struct proto_info const *last)
{
    dump_frame_rec(last);
    printf("\n");
    fflush(stdout);
    return 0;
}

void on_load(void)
{
    SLOG(LOG_INFO, "Dumper loaded\n");
}

void on_unload(void)
{
    SLOG(LOG_INFO, "Dumper unloading\n");
}
