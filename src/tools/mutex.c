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
#include <pthread.h>
#include <time.h>
#include <limits.h>
#include <junkie/config.h>
#ifdef HAVE_SYS_PRCTL_H
#   include <sys/prctl.h>
#endif
#include <junkie/tools/mutex.h>
#include <junkie/tools/log.h>
#include <junkie/tools/tempstr.h>
#include <junkie/tools/ext.h>
#include <junkie/tools/timeval.h>

static char const Id[] = "$Id$";

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
    int const err = pthread_mutex_lock(&mutex->mutex);
    if (! err) {
        SLOG(LOG_DEBUG, "Locked %s", mutex_name(mutex));
    } else {
        SLOG(LOG_ERR, "Cannot lock %s: %s", mutex_name(mutex), strerror(err));
        // so be it
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

void mutex_ctor(struct mutex *mutex, char const *name)
{
    mutex_ctor_with_type(mutex, name, PTHREAD_MUTEX_ERRORCHECK);
}

void mutex_dtor(struct mutex *mutex)
{
    assert(mutex->name);
    SLOG(LOG_DEBUG, "Destruct mutex %s", mutex_name(mutex));
    (void)pthread_mutex_destroy(&mutex->mutex);
    mutex->name = NULL;
}

/*
 * Supermutexes
 */

static char const *supermutex_name(struct supermutex const *super)
{
    return tempstr_printf("%s@%p", super->mutex.name, super);
}

void supermutex_ctor(struct supermutex *super, char const *name)
{
    SLOG(LOG_DEBUG, "Construct supermutex %s@%p", name, super);
    super->rec_count = 0;
    super->owner = (pthread_t)0;
    pthread_rwlock_init(&super->metalock, NULL);
    mutex_ctor_with_type(&super->mutex, name, PTHREAD_MUTEX_NORMAL);    // Other types may not allow timed lock
}

void supermutex_dtor(struct supermutex *super)
{
    SLOG(LOG_DEBUG, "Destruct supermutex %s", supermutex_name(super));
    pthread_rwlock_destroy(&super->metalock);
    mutex_dtor(&super->mutex);
}

static int metalock_r(struct supermutex *super)
{
    int const err = pthread_rwlock_rdlock(&super->metalock);
    if (err) {
        SLOG(LOG_ERR, "Cannot get reader metalock for %s: %s", supermutex_name(super), strerror(err));
    }
    return err;
}

static int metalock_w(struct supermutex *super)
{
    int const err = pthread_rwlock_wrlock(&super->metalock);
    if (err) {
        SLOG(LOG_ERR, "Cannot get writer metalock for %s: %s", supermutex_name(super), strerror(err));
    }
    return err;
}

static void metaunlock(struct supermutex *super)
{
    int const err = pthread_rwlock_unlock(&super->metalock);
    if (err) {
        SLOG(LOG_CRIT, "Cannot unlock metalock for %s: %s", supermutex_name(super), strerror(err));
    }
}

int supermutex_lock(struct supermutex *super)
{
    pthread_t const self = pthread_self();
    if (0 != metalock_r(super)) return MUTEX_SYS_ERROR;
    if (super->owner == self) {
        if (super->rec_count == INT_MAX) {
            metaunlock(super);
            SLOG(LOG_CRIT, "Too many recursive locking of supermutex %s", supermutex_name(super));
            return MUTEX_TOO_MANY_RECURS;
        }
        super->rec_count ++;
        metaunlock(super);
        return 0;
    }

    // We are not the owner of the lock
    metaunlock(super);
    SLOG(LOG_DEBUG, "Locking supermutex %s", supermutex_name(super));
    // From now on the metadata can change, but we shall not become the owner of the lock
#   define USEC_DEADLOCK 100000 // 100ms
    struct timeval now;
    timeval_set_now(&now);
    timeval_add_usec(&now, USEC_DEADLOCK);
    int const err = pthread_mutex_timedlock(&super->mutex.mutex, &(struct timespec){ .tv_sec = now.tv_sec, .tv_nsec = now.tv_usec*1000ULL });
    if (err == ETIMEDOUT) {
        SLOG(LOG_ERR, "Deadlock while waiting for supermutex %s", supermutex_name(super));
        return MUTEX_DEADLOCK;
    } else if (err != 0) {
        SLOG(LOG_ERR, "Cannot pthread_mutex_timedlock() supermutex %s: %s", supermutex_name(super), strerror(err));
        return MUTEX_SYS_ERROR;
    }
    // So we now own the lock
    if (0 != metalock_w(super)) {
        (void)pthread_mutex_unlock(&super->mutex.mutex);
        return MUTEX_SYS_ERROR;
    }
    super->owner = self;
    super->rec_count = 1;
    metaunlock(super);
    SLOG(LOG_DEBUG, "Locked supermutex %s", supermutex_name(super));
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
    pthread_t const self = pthread_self();
    metalock_r(super);
    assert(super->owner == self);
    assert(super->rec_count > 0);
    if (--super->rec_count == 0) {
        super->owner = (pthread_t)0;
        metaunlock(super);
        mutex_unlock(&super->mutex);
    } else {
        metaunlock(super);
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
 * Init
 */

void mutex_init(void)
{
    log_category_mutex_init();

    ext_function_ctor(&sg_set_thread_name,
        "set-thread-name", 1, 0, 0, g_set_thread_name,
        "(set-thread-name \"thing\"): set current thread name.\n");
}

void mutex_fini(void)
{
    log_category_mutex_fini();
}
