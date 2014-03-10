// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2013, SecurActive.
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
#include <unistd.h>
#include <string.h>
#include <libguile.h>
#include "junkie/tools/miscmacs.h"
#include "junkie/tools/log.h"
#include "junkie/tools/mutex.h"
#include "junkie/tools/timebound.h"

LOG_CATEGORY_DEF(timebound)
#undef LOG_CAT
#define LOG_CAT timebound_log_category

/** Gives us an idea of current time (remember we may be using pcap timestamps).
 * No need to be very accurate here. */
static time_t volatile last_used;

/*
 * Timebound Pools
 */

static struct mutex timebound_pools_mutex;  // protects timebound_pools
static LIST_HEAD(timebound_pools, timebound_pool) timebound_pools;

void timebound_pool_ctor(struct timebound_pool *pool, char const *name, unsigned const *timeout, void (*del)(struct timebound *))
{
    SLOG(LOG_DEBUG, "Construct timebound_pool@%p for %s", pool, name);

    assert(timeout);
    pool->name = name;
    pool->timeout = timeout;
    pool->del = del;
    pool->next_bucket = 0;    // to please valgrind, but any value would do
    for (unsigned p = 0; p < NB_ELEMS(pool->buckets); p++) {
        struct timebound_bucket *const bucket = pool->buckets + p;
        mutex_ctor_recursive(&bucket->mutex, "timebound_pool bucket");
        TAILQ_INIT(&bucket->list);
    }
    WITH_LOCK(&timebound_pools_mutex) {
        LIST_INSERT_HEAD(&timebound_pools, pool, entry);
    }
}

void timebound_pool_dtor(struct timebound_pool *pool)
{
    SLOG(LOG_DEBUG, "Destruct timebound_pool@%p (%s)", pool, pool->name);

    WITH_LOCK(&timebound_pools_mutex) {
        LIST_REMOVE(pool, entry);
    }

    for (unsigned p = 0; p < NB_ELEMS(pool->buckets); p++) {
        struct timebound_bucket *const bucket = pool->buckets + p;
        struct timebound *t;
        while (NULL != (t = TAILQ_LAST(&bucket->list, timebounds))) {
            pool->del(t);
        }
        mutex_dtor(&bucket->mutex);
    }
}

void timebound_ctor(struct timebound *t, struct timebound_pool *pool, struct timeval const *now)
{
    SLOG(LOG_DEBUG, "Construct timebound object@%p, pool@%p (%s)", t, pool, pool->name);

    unsigned const b = pool->next_bucket ++;
    struct timebound_bucket *const bucket = pool->buckets + (b % NB_ELEMS(pool->buckets));
    t->bucket = bucket;
    t->monitored = true;
    SLOG(LOG_DEBUG, "...bucket=%p", bucket);
    t->last_used = now->tv_sec;
    WITH_LOCK(&bucket->mutex) {
        TAILQ_INSERT_HEAD(&bucket->list, t, entry);
    }
}

void timebound_dtor(struct timebound *t)
{
    SLOG(LOG_DEBUG, "Destruct timebound object@%p", t);
    SLOG(LOG_DEBUG, "...bucket=%p", t->bucket);

    t->monitored = false;
#   ifdef __GNUC__
    __sync_synchronize();   // flush this *before* unlisting
#   else
    // ?
#   endif
    struct mutex *mutex = &t->bucket->mutex;
    WITH_LOCK(mutex) {
        TAILQ_REMOVE(&t->bucket->list, t, entry);
        t->bucket = NULL;   // will catch double destruction
    }
}

void timebound_touch(struct timebound *t, struct timeval const *now)
{
#   ifdef __GNUC__
    __sync_synchronize();   // read actual t->monitored
#   else
    // ?
#   endif
    if (! t->monitored) return;
    // TODO timebound can be destroyed between the monitored check and the mutex lock

    SLOG(LOG_DEBUG, "Touching timebound object @%p", t);
    WITH_LOCK(&t->bucket->mutex) {
        if (t->monitored) {
            TAILQ_REMOVE(&t->bucket->list, t, entry);
            TAILQ_INSERT_HEAD(&t->bucket->list, t, entry);
        }
    }
    last_used = t->last_used = now->tv_sec;
}

/*
 * Timeouter Thread
 */

static pthread_t timebounder_pth;
static struct bench_event timebounding;

static void *timebounder_thread_(void unused_ *dummy)
{
    set_thread_name("J-timebounder");
    disable_cancel();

    while (1) {
        uint64_t start = bench_event_start();
        WITH_LOCK(&timebound_pools_mutex) {
            struct timebound_pool *pool;
            LIST_FOREACH(pool, &timebound_pools, entry) {
                unsigned const timeout = *pool->timeout;
                if (! timeout) continue;
                time_t max_last_used = last_used - timeout;

                SLOG(LOG_DEBUG, "Timeouting timebound_pool@%p (%s), which timeout=%u", pool, pool->name, timeout);
                for (unsigned p = 0; p < NB_ELEMS(pool->buckets); p++) {
                    struct timebound_bucket *const bucket = pool->buckets + p;
                    WITH_LOCK(&bucket->mutex) {
                        // from last to first
                        struct timebound *t, *tmp;
                        TAILQ_FOREACH_REVERSE_SAFE(t, &bucket->list, timebounds, entry, tmp) {
                            if (t->last_used > max_last_used) break;

                            SLOG(LOG_DEBUG, "Timeouting timebound object@%p", t);
                            pool->del(t);
                        }
                    }
                }
            }
        }
        bench_event_stop(&timebounding, start);

        // Wait
        cancellable_sleep(1);
    }

    return NULL;
}

static void *timebounder_thread(void *dummy)
{
    return scm_with_guile(timebounder_thread_, dummy);
}

/*
 * Init
 */

static unsigned inited;
void timebound_init(void)
{
    if (inited++) return;
    mutex_init();

    mutex_ctor(&timebound_pools_mutex, "timebound pools");
    LIST_INIT(&timebound_pools);
    log_category_timebound_init();
    bench_event_ctor(&timebounding, "timeout timebound objects");

    int err = pthread_create(&timebounder_pth, NULL, timebounder_thread, NULL);

    if (err) {
        SLOG(LOG_ERR, "Cannot pthread_create(): %s", strerror(err));
    }
}

void timebound_fini(void)
{
    if (--inited) return;

    // Kill timebounder thread
    SLOG(LOG_DEBUG, "Terminating timebounder thread...");
    (void)pthread_cancel(timebounder_pth);
    (void)pthread_join(timebounder_pth, NULL);

    bench_event_dtor(&timebounding);

#   ifdef DELETE_ALL_AT_EXIT
    // timebound_pools?
    mutex_dtor(&timebound_pools_mutex);
#   endif
    log_category_timebound_fini();

    mutex_fini();
}
