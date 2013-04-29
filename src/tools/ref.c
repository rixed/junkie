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
#include <unistd.h>
#include <string.h>
#include <libguile.h>
#include "junkie/tools/log.h"
#include "junkie/tools/ref.h"
#include "junkie/tools/mutex.h"
#include "junkie/tools/bench.h"

LOG_CATEGORY_DEF(ref)
#undef LOG_CAT
#define LOG_CAT ref_log_category

/* We proceed as follow :
 * There is a RW lock that all threads try to take for read, and the doomer
 * thread that takes it for write from time to time.
 */

static struct rwlock rwlock;

void enter_unsafe_region(void)
{
    rwlock_acquire(&rwlock, false);
}

void enter_safe_region(void)
{
    rwlock_release(&rwlock);
}

static pthread_t doomer_pth;

extern struct refs death_row;
extern struct mutex death_row_mutex;

static void delete_doomed(void)
{
    static struct bench_event dooming = BENCH("del doomed objs");
    uint64_t start = bench_event_start();

    SLOG(LOG_DEBUG, "Deleting doomed objects...");
    unsigned nb_dels = 0, nb_rescued = 0;

    // No need to take the mutex since other threads are not allowed to reenter unsafe region until we are done

    struct ref *r;
    while (NULL != (r = SLIST_FIRST(&death_row))) {
        // Beware that r->del() may doom further objects, which will be added at the beginning of the list.
        SLOG(LOG_DEBUG, "Delete next object on doom list: %p", r);
        SLIST_REMOVE_HEAD(&death_row, entry);
        r->entry.sle_next = NOT_IN_DEATH_ROW;
        if (r->count == 0) {
            r->del(r);
            nb_dels ++;
        } else {
            nb_rescued ++;
        }
    }

    SLOG(nb_dels + nb_rescued > 0 ? LOG_INFO:LOG_DEBUG, "Deleted %u objects, rescued %u", nb_dels, nb_rescued);

    bench_event_stop(&dooming, start);
}

void doomer_run(void)
{
    rwlock_acquire(&rwlock, true);
    delete_doomed();
    rwlock_release(&rwlock);
}

static void *doomer_thread_(void unused_ *dummy)
{
    set_thread_name("J-doomer");

    while (1) {
        doomer_run();
        sleep(1);
    }
    return NULL;
}

static void *doomer_thread(void *data)
{
    return scm_with_guile(doomer_thread_, data);
}

extern inline void ref_ctor(struct ref *, void (*del)(struct ref *));
extern inline void ref_dtor(struct ref *);
extern inline void *ref(struct ref *);
extern inline void unref(struct ref *);

void doomer_stop(void)
{
    rwlock_acquire(&rwlock, false);    // wait for doomer-thread to finish its run
    (void)pthread_cancel(doomer_pth);
    (void)pthread_join(doomer_pth, NULL);
    rwlock_release(&rwlock);
    SLOG(LOG_DEBUG, "doomer thread was cancelled");
}

static unsigned inited;
void ref_init(void)
{
    if (inited++) return;
    mutex_init();

    mutex_ctor(&death_row_mutex, "death row");
    SLIST_INIT(&death_row);
    log_category_ref_init();
    rwlock_ctor(&rwlock, "doomer");

    int err = pthread_create(&doomer_pth, NULL, doomer_thread, NULL);

    if (! err) {
        pthread_detach(doomer_pth);
    } else {
        SLOG(LOG_ERR, "Cannot pthread_create(): %s", strerror(err));
    }
}

void ref_fini(void)
{
    if (--inited) return;

    rwlock_dtor(&rwlock);
    mutex_dtor(&death_row_mutex);
    log_category_ref_fini();

    mutex_fini();
}

