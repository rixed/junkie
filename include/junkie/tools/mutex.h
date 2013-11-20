// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef MUTEX_H_100914
#define MUTEX_H_100914
#include <pthread.h>
#include <errno.h>
#include <junkie/config.h>
#include <junkie/cpp.h>
#include <junkie/tools/queue.h>
#include <junkie/tools/bench.h>

/** @file
 * @brief Wrappers around pthread_mutex_t
 */

struct mutex {
    pthread_mutex_t mutex;
    char const *name;
    struct bench_atomic_event lock_for_free;
    struct bench_event acquiring_lock;
};

void mutex_lock(struct mutex *);
void mutex_unlock(struct mutex *);
void mutex_unlock_(void *);   ///< Same as mutex_unlock but comply to scm_dynwind_unwind_handler signature
/// Grab the two mutexes, first the one with smaller address.
/** Useful to avoid some deadlocks. */
void mutex_lock2(struct mutex *restrict, struct mutex *restrict);
void mutex_unlock2(struct mutex *restrict, struct mutex *restrict);
/// Beware that the name is *not* strduped
void mutex_ctor(struct mutex *, char const *name);
void mutex_ctor_recursive(struct mutex *, char const *);
void mutex_ctor_with_type(struct mutex *, char const *, int);
void mutex_dtor(struct mutex *);

struct mutex_pool {
    struct mutex locks[CPU_MAX*11];
};

void mutex_pool_ctor(struct mutex_pool *, char const *name);
void mutex_pool_dtor(struct mutex_pool *);
struct mutex *mutex_pool_anyone(struct mutex_pool *);

/// Assert you own a lock (works only for mutex created without the RECURSIVE attribute !)
#define PTHREAD_ASSERT_LOCK(mutex) assert(EDEADLK == pthread_mutex_lock(mutex))

void set_thread_name(char const *name);
char const *get_thread_name(void);

void mutex_init(void);
void mutex_fini(void);

#define LIST_LOOKUP_LOCKED(var, head, field, cond, mutex) do { \
    mutex_lock(mutex); \
    LIST_LOOKUP(var, head, field, cond); \
    mutex_unlock(mutex); \
} while (0)

#define SLIST_LOOKUP_LOCKED(var, head, field, cond, mutex) do { \
    mutex_lock(mutex); \
    SLIST_LOOKUP(var, head, field, cond); \
    mutex_unlock(mutex); \
} while (0)

#define WITH_LOCK(lock) \
    mutex_lock(lock); \
    for (bool first__ = true ; first__ || (mutex_unlock(lock), false) ; first__ = false)

#define WITH_PTH_MUTEX(lock) \
    pthread_mutex_lock(lock); \
    for (bool first__ = true ; first__ || (pthread_mutex_unlock(lock), false) ; first__ = false)

/*
 * Supermutexes - recursive, deadlock protected locks.
 */

struct supermutex_user_lock {
    unsigned rec_count;             /// how many time do I own this lock. Not protected, only the actual user can read/write this
    struct supermutex *supermutex;  /// set if I'm owning or waiting this lock, ie the list entry is valid. only written by actual user with supermutex_meta_lock (so can be read by others with supermutex_meta_lock).
    LIST_ENTRY(supermutex_user_lock) entry; /// in the supermutex->holders list, protected by supermutex_meta_lock
    struct supermutex_user *user;   /// backlink
};

/// A supermutex is a mutex wich allow recursive lock while preventing deadlocks
struct supermutex {
    struct mutex mutex;
    LIST_HEAD(supermutex_user_locks, supermutex_user_lock) holders;   // List of threads that are waiting for this supermutex + the one that holds it, protected by supermutex_meta_lock
};

void supermutex_ctor(struct supermutex *, char const *name);
void supermutex_dtor(struct supermutex *);

#define MUTEX_DEADLOCK        (-1)
#define MUTEX_TOO_MANY_RECURS (-2)
#define MUTEX_SYS_ERROR       (-3)
/// @return 0 if the lock was granted, MUTEX_DEADLOCK in case of deadlock, MUTEX_TOO_MANY_RECURS in case of too many recursion, MUTEX_SYS_ERROR in other error cases
int warn_unused supermutex_lock(struct supermutex *);

/// For those cases when you are ready to wait forever
void supermutex_lock_maydeadlock(struct supermutex *);

/// Will abort if you are not the owner of the lock
void supermutex_unlock(struct supermutex *);

/// RWlock
struct rwlock {
    pthread_rwlock_t lock;
    char const *name;
    struct bench_event acquiring_read_lock;
    struct bench_event acquiring_write_lock;
};

void rwlock_ctor(struct rwlock *, char const *name);
void rwlock_dtor(struct rwlock *);
void rwlock_acquire(struct rwlock *, bool write);
void rwlock_release(struct rwlock *);
void rwlock_release_(void *);   ///< Same as rwlock_release but comply to scm_dynwind_unwind_handler signature

#define WITH_READ_LOCK(lock) \
    rwlock_acquire(lock, false); \
    for (bool first__ = true ; first__ || (rwlock_release(lock), false) ; first__ = false)

#define WITH_WRITE_LOCK(lock) \
    rwlock_acquire(lock, true); \
    for (bool first__ = true ; first__ || (rwlock_release(lock), false) ; first__ = false)

void disable_cancel(void);
void enable_cancel(void);
/// Like sleep, but allow a not cancellable thread to be killed in its sleep
/// (Hint: do not go in bed with a lock)
void cancellable_sleep(int);

#endif
