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
#include <junkie/config.h>
#ifdef HAVE_SYS_PRCTL_H
#   include <sys/prctl.h>
#endif
#include <junkie/tools/mutex.h>
#include <junkie/tools/log.h>
#include <junkie/tools/tempstr.h>
#include <junkie/tools/ext.h>

static char const *mutex_name(struct mutex const *mutex)
{
    return tempstr_printf("%s@%p", mutex->name, mutex);
}

void mutex_lock(struct mutex *mutex)
{
    assert(mutex->name);
    SLOG(LOG_DEBUG, "Locking %s", mutex_name(mutex));
    int err = pthread_mutex_lock(&mutex->mutex);
    if (err) {
        SLOG(LOG_ERR, "Cannot lock %s : %s", mutex_name(mutex), strerror(err));
        // so be it
    }
}

void mutex_unlock(struct mutex *mutex)
{
    assert(mutex->name);
    SLOG(LOG_DEBUG, "Unlocking %s", mutex_name(mutex));
    int err = pthread_mutex_unlock(&mutex->mutex);
    if (err) {
        SLOG(LOG_ERR, "Cannot unlock %s : %s", mutex_name(mutex), strerror(err));
    }
}

void mutex_ctor_with_type(struct mutex *mutex, char const *name, int type)
{
    assert(name);
    SLOG(LOG_DEBUG, "Construct mutex %s@%p", name, mutex);
    int err;

    mutex->name = name;

    pthread_mutexattr_t attr;
    err = pthread_mutexattr_init(&attr);
    if (err) SLOG(LOG_ERR, "Cannot init attr for mutex %s@%p : %s", name, mutex, strerror(err));
    err = pthread_mutexattr_settype(&attr, type);
    if (err) SLOG(LOG_ERR, "Cannot set type %d attr of mutex %s@%p : %s", type, name, mutex, strerror(err));
    err = pthread_mutex_init(&mutex->mutex, &attr);
    if (err) SLOG(LOG_ERR, "Cannot create mutex %s@%p : %s", name, mutex, strerror(err));
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
    ext_function_ctor(&sg_set_thread_name,
        "set-thread-name", 1, 0, 0, g_set_thread_name,
        "(set-thread-name \"thing\") : set current thread name.\n");
}

void mutex_fini(void)
{
}
