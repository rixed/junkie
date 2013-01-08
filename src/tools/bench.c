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
#include <pthread.h>
#include "junkie/tools/tempstr.h"
#include "junkie/tools/log.h"
#include "junkie/tools/bench.h"

LOG_CATEGORY_DEF(bench)
#undef LOG_CAT
#define LOG_CAT bench_log_category

extern inline uint64_t rdtsc(void);

/* We accumulate several counters with same name into a repport.
 * Reports are displayed at the end. */

struct report {
    LIST_ENTRY (report) entry;
    enum report_type { REPORT_ATOMIC, REPORT_EVENT } type;
    unsigned count;
    union {
        struct bench_atomic_event atomic;
        struct bench_event event;
    } u;
};

static LIST_HEAD(reports, report) reports;
static pthread_mutex_t report_lock;

static void report_dump(struct report const *report)
{
    switch (report->type) {
        case REPORT_ATOMIC:;
            struct bench_atomic_event const *a = &report->u.atomic;
            // Log result
            // Note: by the time we destruct a bench log module will already be initialized
            if (a->count > 0) {
                SLOG(LOG_INFO, "%30.30s(x%6u): %"PRIu64" times", a->name, report->count, a->count);
            }
            break;
        case REPORT_EVENT:;
            struct bench_event const *e = &report->u.event;
            // Log result
            if (e->count.count > 0) {
                SLOG(LOG_INFO, "%30.30s(x%6u): %"PRIu64" times, tot:%"PRIu64", min:%"PRIu64" avg:%"PRIu64" max:%"PRIu64"",
                    e->count.name, report->count, e->count.count, e->tot_duration,
                    e->min_duration, e->tot_duration / e->count.count, e->max_duration);
            }
            break;
    }
}

static void report_ctor(struct report *report, enum report_type type, char const *name)
{
    SLOG(LOG_DEBUG, "Construct report for %s", name);

    report->count = 0;
    report->type = type;

    switch (type) {
        case REPORT_ATOMIC:
            bench_atomic_event_ctor(&report->u.atomic, name);   // FIXME: save strdup of the name
            break;
        case REPORT_EVENT:
            bench_event_ctor(&report->u.event, name);
            break;
    }

    LIST_INSERT_HEAD(&reports, report, entry);
}

static struct report *report_new(enum report_type type, char const *name)
{
    struct report *report = malloc(sizeof(*report));
    if (! report) return NULL;
    report_ctor(report, type, name);
    return report;
}

static char const *report_name(struct report *report)
{
    switch (report->type) {
        case REPORT_ATOMIC: return report->u.atomic.name;
        case REPORT_EVENT:  return report->u.event.count.name;
    }
    assert(!"Invalid report");
}

// Same as below but do not report it (usefull for bench_event and report itself)
static void bench_atomic_event_dtor_(struct bench_atomic_event *e)
{
#   ifdef WITH_BENCH
    // Destruct
    if (e->name_malloced) {
        free(e->name);
        e->name = NULL;
    }
#   else
    (void)e;
#   endif
}

void bench_event_dtor_(struct bench_event *e)
{
#   ifdef WITH_BENCH
    // Destroy (without producing a report)
    bench_atomic_event_dtor_(&e->count);
#   else
    (void)e;
#   endif
}

static void report_dtor(struct report *report)
{
    SLOG(LOG_DEBUG, "Destruct report for %s", report_name(report));

    LIST_REMOVE(report, entry);

    switch (report->type) {
        case REPORT_ATOMIC:
            bench_atomic_event_dtor_(&report->u.atomic);
            break;
        case REPORT_EVENT:
            bench_event_dtor_(&report->u.event);
            break;
    }
}

static void report_del(struct report *report)
{
    report_dtor(report);
    free(report);
}

// Caller must own report_lock
static struct report *report_lookup_or_create(enum report_type type, char const *name)
{
    struct report *report;
    LIST_LOOKUP(report, &reports, entry, report->type == type && 0 == strcmp(name, report_name(report)));
    if (report) return report;

    return report_new(type, name);
}

// Then the individual bench counters

void bench_atomic_event_ctor(struct bench_atomic_event *e, char const *name)
{
#   ifdef WITH_BENCH
    e->count = 0;
    e->name = strdup(name);
    e->name_malloced = true;
#   else
    (void)e;
    (void)name;
#   endif
}

void bench_atomic_event_dtor(struct bench_atomic_event *e)
{
#   ifdef WITH_BENCH
    // Add this result into the proper report
    (void)pthread_mutex_lock(&report_lock);
    struct report *report = report_lookup_or_create(REPORT_ATOMIC, e->name);
    if (report) {
        report->count ++;
        report->u.atomic.count += e->count;
    }
    (void)pthread_mutex_unlock(&report_lock);

    bench_atomic_event_dtor_(e);
#   else
    (void)e;
#   endif
}

extern inline void bench_event_fire(struct bench_atomic_event *);

extern inline void bench_event_ctor(struct bench_event *e, char const *name)
{
#   ifdef WITH_BENCH
    bench_atomic_event_ctor(&e->count, name);
    e->tot_duration = 0;
    e->min_duration = UINT64_MAX;
    e->max_duration = 0;
#   else
    (void)e;
    (void)name;
#   endif
}

void bench_event_dtor(struct bench_event *e)
{
#   ifdef WITH_BENCH
    // Add this result into the proper report
    (void)pthread_mutex_lock(&report_lock);
    struct report *report = report_lookup_or_create(REPORT_EVENT, e->count.name);
    if (report) {
        report->count ++;
        report->u.event.count.count += e->count.count;
        report->u.event.tot_duration += e->tot_duration;
        if (e->min_duration < report->u.event.min_duration) report->u.event.min_duration = e->min_duration;
        if (e->max_duration > report->u.event.max_duration) report->u.event.max_duration = e->max_duration;
    }
    (void)pthread_mutex_unlock(&report_lock);

    // Destroy (without producing a report)
    bench_atomic_event_dtor_(&e->count);
#   else
    (void)e;
#   endif
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

    log_category_bench_init();
    LIST_INIT(&reports);
    (void)pthread_mutex_init(&report_lock, NULL);
}

static int report_cmp(void const *a_, void const *b_)
{
    struct report const *a = *(struct report const **)a_;
    struct report const *b = *(struct report const **)b_;

    switch (a->type) {
        case REPORT_ATOMIC:
            if (b->type == REPORT_EVENT) return -1;
            assert(b->type == REPORT_ATOMIC);
            if (a->u.atomic.count < b->u.atomic.count) return -1;
            if (a->u.atomic.count > b->u.atomic.count) return 1;
            break;
        case REPORT_EVENT:
            if (b->type == REPORT_ATOMIC) return 1;
            assert(b->type == REPORT_EVENT);
            if (a->u.event.tot_duration < b->u.event.tot_duration) return -1;
            if (a->u.event.tot_duration > b->u.event.tot_duration) return 1;
            break;
    }
    return 0;
}

void bench_fini(void)
{
    if (--inited) return;

    SLOG(LOG_DEBUG, "Fini bench...");

    // Dump reports (sorted)
    unsigned length = 0;
    struct report *report;
    LIST_FOREACH(report, &reports, entry) length++;
    struct report const *arr[length];
    unsigned i = 0;
    LIST_FOREACH(report, &reports, entry) {
        arr[i++] = report;
    }
    qsort(arr, length, sizeof(arr[0]), report_cmp);
    for (i = 0; i < length; i++) {
        report_dump(arr[i]);
    }

    // Dell all reports
    while (NULL != (report = LIST_FIRST(&reports))) {
        report_del(report);
    }

    log_category_bench_fini();
    (void)pthread_mutex_destroy(&report_lock);
}

