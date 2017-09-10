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

void enter_multi_region(void)
{
    rwlock_acquire(&rwlock, false);
}

void enter_mono_region(void)
{
    rwlock_acquire(&rwlock, true);
}

void leave_protected_region(void)
{
    rwlock_release(&rwlock);
}

static pthread_t doomer_pth;

struct refs death_row;
struct mutex death_row_mutex;

static struct bench_event dooming;

void doomer_run(void)
{
    enter_mono_region();

    SLOG(LOG_DEBUG, "Deleting doomed objects...");
    unsigned nb_dels = 0, nb_rescued = 0;

    // Bench time spent scanning death_row
    uint64_t start = bench_event_start();

    // Rescue from death_row the objects which ref count is > 0,
    // and queue into kill_list the one no longer accessible (they can not even reach each others)
    struct refs to_kill;
    SLIST_INIT(&to_kill);
    struct ref *r;
    while (NULL != (r = SLIST_FIRST(&death_row))) {
        SLIST_REMOVE_HEAD(&death_row, entry);
        if (r->count == 0) {
            SLIST_INSERT_HEAD(&to_kill, r, entry);
            nb_dels ++;
        } else {
            r->entry.sle_next = NOT_IN_DEATH_ROW;
            nb_rescued ++;
        }
    }

    SLOG(nb_dels + nb_rescued > 0 ? LOG_INFO:LOG_DEBUG, "Deleted %u objects, rescued %u", nb_dels, nb_rescued);

    bench_event_stop(&dooming, start);

    // No need to block parsing any more since the selected objects are not accessible
    leave_protected_region();

    enter_multi_region();   // should not compete with mono_region anyway.

    // Delete all selected objects
    while (NULL != (r = SLIST_FIRST(&to_kill))) {
        assert(r->count == 0);
        // Beware that r->del() may doom further objects, which will be added in the death_row for next run
        SLOG(LOG_DEBUG, "Delete next object on kill list: %p", r);
        SLIST_REMOVE_HEAD(&to_kill, entry);
        r->entry.sle_next = NULL;   // the deletor must not care about the ref (since the decision to del the object was already taken)
        r->del(r);
    }

    leave_protected_region();
}

static void *doomer_thread_(void unused_ *dummy)
{
    set_thread_name("J-doomer");
    disable_cancel();
    while (1) {
        doomer_run();
        cancellable_sleep(1);
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
    SLOG(LOG_DEBUG, "Cancelling doomer-thread");
    if (0 != pthread_cancel(doomer_pth)) {
        SLOG(LOG_CRIT, "Cannot cancel doomer thread!");
    }
    if (0 != pthread_join(doomer_pth, NULL)) {
        SLOG(LOG_CRIT, "Cannot join doomer thread!");
    }
    SLOG(LOG_DEBUG, "doomer thread was cancelled");
}

static unsigned inited;
void ref_init(void)
{
    if (inited++) return;
    mutex_init();
    bench_init();

    bench_event_ctor(&dooming, "del doomed objs");
    mutex_ctor(&death_row_mutex, "death row");
    SLIST_INIT(&death_row);
    log_category_ref_init();
    rwlock_ctor(&rwlock, "doomer");

    int err = pthread_create(&doomer_pth, NULL, doomer_thread, NULL);

    if (err) {
        SLOG(LOG_ERR, "Cannot pthread_create(): %s", strerror(err));
    }
}

void ref_fini(void)
{
    if (--inited) return;

#   ifdef DELETE_ALL_AT_EXIT
    rwlock_dtor(&rwlock);
    mutex_dtor(&death_row_mutex);
#   endif
    log_category_ref_fini();
    bench_event_dtor(&dooming);

    bench_fini();
    mutex_fini();
}

