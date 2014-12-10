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
#include <time.h>
#include <limits.h>
#include <stdint.h>
#include "junkie/config.h"
#ifdef HAVE_SYS_PRCTL_H
#   include <sys/prctl.h>
#endif
#include "junkie/tools/mutex.h"
#include "junkie/tools/log.h"
#include "junkie/tools/tempstr.h"
#include "junkie/tools/ext.h"
#include "junkie/tools/timeval.h"
#include "junkie/tools/bench.h"

LOG_CATEGORY_DEF(mutex)
#undef LOG_CAT
#define LOG_CAT mutex_log_category

static char const *mutex_name(struct mutex const *mutex)
{
    return tempstr_printf("%s@%p", mutex->name, mutex);
}

void mutex_lock(struct mutex *mutex)
{
    assert(mutex->name);
    SLOG(LOG_DEBUG, "Locking %s", mutex_name(mutex));
    uint64_t const start = bench_event_start();
#   ifdef WITH_BENCH
    int err = pthread_mutex_trylock(&mutex->mutex);
    switch (err) {
        case 0:
            bench_event_fire(&mutex->lock_for_free);
            break;
        case EBUSY:
            err = pthread_mutex_lock(&mutex->mutex);
            break;
        default:
            // other errors (for lock and trylock) handled below
            break;
    }
#   else
    // This was found to be noticably faster (-1% cpu load)
    int err = pthread_mutex_lock(&mutex->mutex);
#   endif
    if (! err) {
        bench_event_stop(&mutex->acquiring_lock, start);
        SLOG(LOG_DEBUG, "Locked %s", mutex_name(mutex));
    } else {
        SLOG(LOG_ERR, "Cannot lock %s: %s", mutex_name(mutex), strerror(err));
        // better crash than getting a possible deadlock
        assert(!err);
    }
}

void mutex_unlock(struct mutex *mutex)
{
    assert(mutex->name);
    SLOG(LOG_DEBUG, "Unlocking %s", mutex_name(mutex));
    int const err = pthread_mutex_unlock(&mutex->mutex);    // Call directly pthread_mutex_unlock to avoid the logs in mutex_unlock
    if (! err) {
        SLOG(LOG_DEBUG, "Unlocked %s", mutex_name(mutex));
    } else {
        SLOG(LOG_ERR, "Cannot unlock %s: %s", mutex_name(mutex), strerror(err));
    }
}

void mutex_unlock_(void *mutex)
{
    mutex_unlock(mutex);
}

void mutex_lock2(struct mutex *restrict m1, struct mutex *restrict m2)
{
    if (m1 > m2) {
        struct mutex *restrict tmp = m1;
        m1 = m2; m2 = tmp;
    }

    mutex_lock(m1);
    mutex_lock(m2);
}

void mutex_unlock2(struct mutex *restrict m1, struct mutex *restrict m2)
{
    if (m1 > m2) {
        struct mutex *restrict tmp = m1;
        m1 = m2; m2 = tmp;
    }

    mutex_unlock(m2);
    mutex_unlock(m1);
}

void mutex_ctor_with_type(struct mutex *mutex, char const *name, int type)
{
    assert(name);
    SLOG(LOG_DEBUG, "Construct mutex %s@%p", name, mutex);
    int err;

    mutex->name = name;
    bench_atomic_event_ctor(&mutex->lock_for_free, tempstr_printf("%s locked for free", name));
    bench_event_ctor(&mutex->acquiring_lock, tempstr_printf("acquiring %s", name));

    pthread_mutexattr_t attr;
    err = pthread_mutexattr_init(&attr);
    if (err) SLOG(LOG_ERR, "Cannot init attr for mutex %s@%p: %s", name, mutex, strerror(err));
    err = pthread_mutexattr_settype(&attr, type);
    if (err) SLOG(LOG_ERR, "Cannot set type %d attr of mutex %s@%p: %s", type, name, mutex, strerror(err));
    err = pthread_mutex_init(&mutex->mutex, &attr);
    if (err) SLOG(LOG_ERR, "Cannot create mutex %s@%p: %s", name, mutex, strerror(err));
    err = pthread_mutexattr_destroy(&attr);
    if (err) SLOG(LOG_ERR, "Cannot dispose of attr for mutex %s@%p: %s", name, mutex, strerror(err));
}

void mutex_ctor_recursive(struct mutex *mutex, char const *name)
{
    mutex_ctor_with_type(mutex, name, PTHREAD_MUTEX_RECURSIVE);
}

void mutex_ctor(struct mutex *mutex, char const *name)
{
    mutex_ctor_with_type(mutex, name, PTHREAD_MUTEX_ERRORCHECK);
}

void mutex_dtor(struct mutex *mutex)
{
    SLOG(LOG_DEBUG, "Destruct mutex %s", mutex_name(mutex));
    assert(mutex->name);
    bench_atomic_event_dtor(&mutex->lock_for_free);
    bench_event_dtor(&mutex->acquiring_lock);
    (void)pthread_mutex_destroy(&mutex->mutex);
    mutex->name = NULL;
}

/*
 * Supermutexes
 */

static struct mutex supermutex_meta_lock;

/* We cannot use thread local storage for the supermutex_user structure since
 * we want to access them from other threads as well.  Instead, we use thread
 * local storage to store the address of the current thread supermutex_user. */
struct supermutex_user {
    unsigned nb_locks;  /// how many locks I own or wait for
#   define NB_MAX_LOCKED_SUPERMUTEX_PER_THREAD 16
    struct supermutex_user_lock locks[NB_MAX_LOCKED_SUPERMUTEX_PER_THREAD];
};

static __thread struct supermutex_user *my_supermutex_user;


static void supermutex_user_ctor(struct supermutex_user *usr)
{
    usr->nb_locks = 0;
    for (unsigned l = 0; l < NB_ELEMS(usr->locks); l ++) {
        usr->locks[l].user = usr;
    }
}

static struct supermutex_user *supermutex_user_new(void)
{
    struct supermutex_user *usr = malloc(sizeof(*usr)); // we do not use objalloc to avoid circular dependancy here
    if (! usr) {
        SLOG(LOG_CRIT, "Cannot allocate for a supermutex_user! I'm sorry there's no alternative!");
        abort();
    }
    supermutex_user_ctor(usr);
    return usr;
}

// This will never get called, but hopefully no thread will quit with some supermutex locked.
// FIXME: use TLS pthread API to register a finalizer?
#if 0
static void supermutex_user_dtor(struct supermutex_user *usr)
{
    // We are supposed to release our locks first
    assert(usr->nb_locks == 0);
}
#endif

static char const *supermutex_name(struct supermutex const *super)
{
    return tempstr_printf("%s@%p", super->mutex.name, super);
}

void supermutex_ctor(struct supermutex *super, char const *name)
{
    SLOG(LOG_DEBUG, "Construct supermutex %s@%p", name, super);
    mutex_lock(&supermutex_meta_lock);
    mutex_ctor(&super->mutex, name);
    LIST_INIT(&super->holders);
    mutex_unlock(&supermutex_meta_lock);
}

void supermutex_dtor(struct supermutex *super)
{
    SLOG(LOG_DEBUG, "Destruct supermutex %s", supermutex_name(super));
    mutex_lock(&supermutex_meta_lock);
    assert(LIST_EMPTY(&super->holders));
    mutex_dtor(&super->mutex);
    mutex_unlock(&supermutex_meta_lock);
}

/* Starting from the mutex super owned by user usr, try all other threads owning it, and look for cycle back to target.
 * Caller must own supermutex_meta_lock. */
static bool supermutex_is_cycling(struct supermutex_user *usr, struct supermutex *super, struct supermutex_user *target)
{
    // Look for all other threads owning/waiting this supermutex
    struct supermutex_user_lock *sul;
    LIST_FOREACH(sul, &super->holders, entry) {
        struct supermutex_user *const usr_ = sul->user;
        if (usr_ == usr) continue;  // in the special case where usr == target dont report a cycle
        if (usr_ == target) return true;
        // Now look over all *other* locks owned by this other thread
        for (unsigned l = 0; l < usr_->nb_locks; l++) {
            if (! usr_->locks[l].supermutex) continue;
            if (usr_->locks[l].supermutex == super) continue;
            // Can I reach target from this one?
            if (supermutex_is_cycling(usr_, usr_->locks[l].supermutex, target)) return true;
        }
    }

    return false;
}

int supermutex_lock(struct supermutex *super)
{
    if (! my_supermutex_user) {
        my_supermutex_user = supermutex_user_new();
    }

    assert(my_supermutex_user->nb_locks <= NB_ELEMS(my_supermutex_user->locks));

    // Easy case: maybe I already own it?
    unsigned l;
    unsigned free_l = UNSET;
    for (l = 0; l < my_supermutex_user->nb_locks; l++) {
        if (my_supermutex_user->locks[l].supermutex == super) break;
        if (my_supermutex_user->locks[l].supermutex == NULL) free_l = l;
    }
    if (l < my_supermutex_user->nb_locks) {
        SLOG(LOG_DEBUG, "Locking again supermutex %s", supermutex_name(super));
        assert(my_supermutex_user->locks[l].rec_count > 0);

        if (my_supermutex_user->locks[l].rec_count == UINT_MAX) {
            SLOG(LOG_CRIT, "Too many recursive locking of supermutex %s", supermutex_name(super));
            return MUTEX_TOO_MANY_RECURS;
        }
        my_supermutex_user->locks[l].rec_count ++;
        return 0;
    }

    mutex_lock(&supermutex_meta_lock);

    // From this lock (supposed I go for it), look for a circular dependancy
    if (supermutex_is_cycling(my_supermutex_user, super, my_supermutex_user)) {
        SLOG(LOG_INFO, "Locking supermutex %s may deadlock!", supermutex_name(super));
        mutex_unlock(&supermutex_meta_lock);
        return MUTEX_DEADLOCK;
    }

    // Adding me in the list of holders
    if (free_l != UNSET) {
        l = free_l;
    } else {
        if (my_supermutex_user->nb_locks == NB_ELEMS(my_supermutex_user->locks)) {
            SLOG(LOG_ERR, "Cannot lock supermutex %s since I'm holding too many locks already!?", supermutex_name(super));
            mutex_unlock(&supermutex_meta_lock);
            return MUTEX_SYS_ERROR;
        }
        l = my_supermutex_user->nb_locks++;
    }
    my_supermutex_user->locks[l].rec_count = 1;
    my_supermutex_user->locks[l].supermutex = super;
    LIST_INSERT_HEAD(&super->holders, my_supermutex_user->locks+l, entry);

    mutex_unlock(&supermutex_meta_lock);

    // Wait for the lock
    mutex_lock(&super->mutex);

    return 0;
}

void supermutex_lock_maydeadlock(struct supermutex *super)
{
    int err;
    while ((err = supermutex_lock(super)) != 0) {
        switch (err) {
            case MUTEX_DEADLOCK: // retry!
                (void)nanosleep(&(struct timespec){ .tv_sec = 0, .tv_nsec = 1000 }, NULL);
                break;
            default:
                SLOG(LOG_CRIT, "Cannot lock supermutex %s, bailing out!", supermutex_name(super));
                abort();
        }
    }
}

void supermutex_unlock(struct supermutex *super)
{
    SLOG(LOG_DEBUG, "Unlocking supermutex %s", supermutex_name(super));

    assert(my_supermutex_user->nb_locks <= NB_ELEMS(my_supermutex_user->locks));
    assert(my_supermutex_user->nb_locks > 0);

    unsigned l;
    for (l = 0; l < my_supermutex_user->nb_locks; l++) {
        if (my_supermutex_user->locks[l].supermutex == super) break;
    }
    assert(l < my_supermutex_user->nb_locks);  // Or I'm releasing something I do not own?

    if (--my_supermutex_user->locks[l].rec_count > 0) return;

    mutex_lock(&supermutex_meta_lock);

    LIST_REMOVE(my_supermutex_user->locks+l, entry);
    my_supermutex_user->locks[l].supermutex = NULL;
    mutex_unlock(&super->mutex);

    mutex_unlock(&supermutex_meta_lock);

    // Compact nb_locks
    while (my_supermutex_user->nb_locks > 0 && my_supermutex_user->locks[my_supermutex_user->nb_locks-1].supermutex == NULL) {
        my_supermutex_user->nb_locks--;
    }
}

/*
 * Thread names
 */

static __thread char thread_name[64];

void set_thread_name(char const *name)
{
    SLOG(LOG_DEBUG, "set thread name to '%s'", name);

    snprintf(thread_name, sizeof(thread_name), "%s", name);

#   ifdef HAVE_PRCTL
    if (-1 == prctl(PR_SET_NAME, name, 0, 0, 0))
        SLOG(LOG_ERR, "%s (%d)", strerror(errno), errno);
#   endif
}

char const *get_thread_name(void)
{
    return thread_name;
}

static struct ext_function sg_set_thread_name;
static SCM g_set_thread_name(SCM name_)
{
    char *name = scm_to_tempstr(name_);
    set_thread_name(name);
    return SCM_UNSPECIFIED;
}

/*
 * RW locks
 */

static char const *rwlock_name(struct rwlock const *lock)
{
    return tempstr_printf("%s@%p", lock->name, lock);
}

void rwlock_ctor(struct rwlock *lock, char const *name)
{
    assert(name);
    lock->name = name;
    SLOG(LOG_DEBUG, "Construct rwlock %s", rwlock_name(lock));
    int err = pthread_rwlock_init(&lock->lock, NULL);
    if (err) {
        SLOG(LOG_ERR, "Cannot pthread_rwlock_init(): %s", strerror(err));
        // so be it
    }

    bench_event_ctor(&lock->acquiring_read_lock, tempstr_printf("acquiring %s (read)", name));
    bench_event_ctor(&lock->acquiring_write_lock, tempstr_printf("acquiring %s (write)", name));
}

void rwlock_dtor(struct rwlock *lock)
{
    SLOG(LOG_DEBUG, "Destruct rwlock %s", rwlock_name(lock));
    pthread_rwlock_destroy(&lock->lock);
    bench_event_dtor(&lock->acquiring_read_lock);
    bench_event_dtor(&lock->acquiring_write_lock);
}

static void acquire(int (*f)(pthread_rwlock_t *), struct rwlock *lock)
{
    int err = f(&lock->lock);
    if (err) {
        SLOG(LOG_ERR, "Cannot acquire RWLock: %s", strerror(err));
        // so be it
    }
}

void rwlock_acquire(struct rwlock *lock, bool write)
{
    uint64_t const start = bench_event_start();
    pthread_testcancel();
    if (write) {
        acquire(pthread_rwlock_wrlock, lock);
        bench_event_stop(&lock->acquiring_write_lock, start);
    } else {
        acquire(pthread_rwlock_rdlock, lock);
        bench_event_stop(&lock->acquiring_read_lock, start);
    }
}

void rwlock_release(struct rwlock *lock)
{
    int err = pthread_rwlock_unlock(&lock->lock);
    if (err) {
        SLOG(LOG_ERR, "Cannot release RWLock: %s", strerror(err));
        // so be it
    }
}

void rwlock_release_(void *lock)
{
    rwlock_release(lock);
}

/*
 * Mutex pools
 */

void mutex_pool_ctor(struct mutex_pool *p, char const *name)
{
    for (unsigned i = 0; i < NB_ELEMS(p->locks); i++) {
        mutex_ctor(p->locks+i, name);
    }
}

void mutex_pool_dtor(struct mutex_pool *p)
{
    for (unsigned i = 0; i < NB_ELEMS(p->locks); i++) {
        mutex_dtor(p->locks+i);
    }
}

struct mutex *mutex_pool_anyone(struct mutex_pool *p)
{
    static unsigned idx = 0;
    idx = (idx + 1) % NB_ELEMS(p->locks);
    return p->locks + idx;
}


/*
 * Misc
 */

void disable_cancel(void)
{
    int dummy_oldstate;
    if (0 != pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &dummy_oldstate)) {
        SLOG(LOG_ERR, "Cannot pthread_setcancelstate()");
        // so be it
    }
}

void enable_cancel(void)
{
    int dummy_oldstate;
    if (0 != pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &dummy_oldstate)) {
        SLOG(LOG_ERR, "Cannot pthread_setcancelstate()");
    }
}

void cancellable_sleep(int t)
{
    enable_cancel();
    sleep(t);
    disable_cancel();
}

/*
 * Init
 */

static unsigned inited;
void mutex_init(void)
{
    if (
#       ifdef __GNUC__
        __sync_fetch_and_add(&inited, 1)
#       else
        inited++
#       endif
    ) return;

    bench_init();
    ext_init();
    log_init();

    log_category_mutex_init();
    mutex_ctor(&supermutex_meta_lock, "supermutex_meta");

    ext_function_ctor(&sg_set_thread_name,
        "set-thread-name", 1, 0, 0, g_set_thread_name,
        "(set-thread-name \"thing\"): set current thread name.\n");
}

void mutex_fini(void)
{
    if (
#       ifdef __GNUC__
        __sync_sub_and_fetch(&inited, 1)
#       else
        --inited
#       endif
    ) return;

#   ifdef DELETE_ALL_AT_EXIT
    mutex_dtor(&supermutex_meta_lock);
#   endif
    log_category_mutex_fini();

    log_init();
    ext_fini();
    bench_fini();
}
