// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef MUTEX_H_100914
#define MUTEX_H_100914
#include <pthread.h>
#include <errno.h>

/** @file
 * @brief Wrappers around pthread_mutex_t
 */

struct mutex {
    pthread_mutex_t mutex;
    char const *name;
};

void mutex_lock(struct mutex *);
/// Grab the two mutexes, first the one with smaller address.
/** Useful to avoid some deadlocks. */
void mutex_lock2(struct mutex *restrict, struct mutex *restrict);
void mutex_unlock(struct mutex *);
void mutex_ctor(struct mutex *, char const *name);
void mutex_ctor_with_type(struct mutex *, char const *, int);
void mutex_dtor(struct mutex *);

/// Assert you own a lock (works only for mutex created without the RECURSIVE attribute !)
#define PTHREAD_ASSERT_LOCK(mutex) assert(EDEADLK == pthread_mutex_lock(mutex))

void set_thread_name(char const *name);
char const *get_thread_name(void);

void mutex_init(void);
void mutex_fini(void);

#endif
