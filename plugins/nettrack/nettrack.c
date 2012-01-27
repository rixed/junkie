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
/* Here we handle the evolution of states in a graph which vertices
 * are predicates over previous state + new proto info (ie. match functions).
 */
#include <stdlib.h>
#include <stdio.h>
#include "junkie/proto/proto.h"
#include "junkie/cpp.h"
#include "nettrack.h"
#include "graph.h"

LOG_CATEGORY_DEF(nettrack);

int parse_callback(struct proto_info const *last, size_t cap_len, uint8_t const unused_ *packet)
{
    (void)last;
    (void)cap_len;
    (void)packet;
    return 0;
}

void on_load(void)
{
    log_category_nettrack_init();
    SLOG(LOG_INFO, "NetTrack loaded");
    nt_graph_init();
}

void on_unload(void)
{
    SLOG(LOG_INFO, "NetTrack unloading");
    nt_graph_fini();
    log_category_nettrack_fini();
}
