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
#include "junkie/tools/log.h"
#include "junkie/tools/ref.h"

static char const Id[] = "$Id$";

LOG_CATEGORY_DEF(ref)
#undef LOG_CAT
#define LOG_CAT ref_log_category

/* We proceed as follow :
 * There is a RW lock that all threads try to take for read, and the doomer
 * thread that takes it for write from time to time.
 */

static pthread_rwlock_t rwlock;

static void acquire(int (*f)(pthread_rwlock_t *))
{
    int err = f(&rwlock);
    if (err) {
        SLOG(LOG_ERR, "Cannot acquire RWLock: %s", strerror(err));
        // so be it
    }
}

static void release(void)
{
    int err = pthread_rwlock_unlock(&rwlock);
    if (err) {
        SLOG(LOG_ERR, "Cannot release RWLock: %s", strerror(err));
        // so be it
    }
}

void enter_unsafe_region(void)
{
    acquire(pthread_rwlock_rdlock);
}

void enter_safe_region(void)
{
    release();
}

static pthread_t doomer_pth;

extern struct refs death_row;
extern struct mutex death_row_mutex;

static void delete_doomed(void)
{
    SLOG(LOG_INFO, "Deleting doomed objects...");
    unsigned nb_dels = 0, nb_rescued = 0;

    // No need to take the mutex since other threads are not allowed to reenter unsafe region until we are done

    struct ref *r;
    while (NULL != (r = SLIST_FIRST(&death_row))) {
        // Beware that r->del() may doom further objects, which will be added at the beginning of the list.
        SLIST_REMOVE_HEAD(&death_row, entry);
        r->entry.sle_next = NOT_IN_DEATH_ROW;
        if (r->count == 0) {
            r->del(r);
            nb_dels ++;
        } else {
            nb_rescued ++;
        }
    }

    SLOG(LOG_INFO, "Deleted %u objects, rescued %u", nb_dels, nb_rescued);
}

static void *doomer_thread(void unused_ *dummy)
{
    set_thread_name("J-doomer");

    while (1) {
        acquire(pthread_rwlock_wrlock);
        delete_doomed();
        release();
        sleep(1);
    }
    return NULL;
}

void ref_init(void)
{
    mutex_ctor(&death_row_mutex, "death row");
    SLIST_INIT(&death_row);
    log_category_ref_init();
    int err = pthread_rwlock_init(&rwlock, NULL);
    if (err) {
        SLOG(LOG_ERR, "Cannot pthread_rwlock_init(): %s", strerror(err));
        // so be it
    }

    err = pthread_create(&doomer_pth, NULL, doomer_thread, NULL);

    if (! err) {
        pthread_detach(doomer_pth);
    } else {
        SLOG(LOG_ERR, "Cannot pthread_create(): %s", strerror(err));
    }
}

void doomer_stop(void)
{
    acquire(pthread_rwlock_rdlock); // wait for doomer-thread to finish its run
    (void)pthread_cancel(doomer_pth);
    (void)pthread_join(doomer_pth, NULL);
    release();
    SLOG(LOG_DEBUG, "doomer thread was cancelled");
}

void ref_fini(void)
{
    pthread_rwlock_destroy(&rwlock);
    mutex_dtor(&death_row_mutex);
    log_category_ref_fini();
}

extern inline void ref_ctor(struct ref *, void (*del)(struct ref *));
extern inline void ref_dtor(struct ref *);
extern inline void *ref(struct ref *);
extern inline void *unref(struct ref *);
