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
#include "junkie/config.h"
#include "junkie/tools/log.h"
#include "junkie/tools/tempstr.h"
#include "junkie/tools/bench.h"

#undef LOG_CAT
#define LOG_CAT bench_log_category
LOG_CATEGORY_DEF(bench);


extern inline uint64_t rdtsc(void);

void bench_atomic_event_ctor(struct bench_atomic_event *e, char const *name)
{
    SLOG(LOG_DEBUG, "Construct bench atomic event %s@%p", name, e);
    e->count = 0;
    e->name = strdup(name);
    e->name_malloced = true;
}


void bench_atomic_event_dtor(struct bench_atomic_event *e)
{
    SLOG(LOG_DEBUG, "Destruct bench atomic event %s@%p", e->name, e);
    // Log result
    SLOG(LOG_INFO, "Event %s triggered %"PRIu64" times", e->name, e->count);
    if (e->name_malloced) {
        free(e->name);
        e->name = NULL;
    }
}

extern inline void bench_event_fire(struct bench_atomic_event *);

extern inline void bench_event_ctor(struct bench_event *e, char const *name)
{
    SLOG(LOG_DEBUG, "Construct bench event %s@%p", name, e);
    bench_atomic_event_ctor(&e->count, name);
    e->tot_duration = 0;
}

void bench_event_dtor(struct bench_event *e)
{
    SLOG(LOG_DEBUG, "Destruct bench event %s@%p", e->count.name, e);
    // Log result
    SLOG(LOG_INFO, "Event %s avg duration: %"PRIu64" cycles", e->count.name, e->count.count > 0 ? e->tot_duration / e->count.count : 0);
    // Destroy
    bench_atomic_event_dtor(&e->count);
}

extern inline uint64_t bench_event_start(void);
extern inline void bench_event_stop(struct bench_event *, uint64_t);

/*
 * Init
 * We depends on nothing but log.
 */

static unsigned inited;
void bench_init(void)
{
    if (inited++) return;

    log_init();
    log_category_bench_init();
}

void bench_fini(void)
{
    if (--inited) return;

    log_category_bench_fini();
    log_fini();
}

