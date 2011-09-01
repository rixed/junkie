// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef MUTEX_H_100914
#define MUTEX_H_100914
#include <pthread.h>
#include <errno.h>
#include <junkie/cpp.h>
#include <junkie/tools/queue.h>

/** @file
 * @brief Wrappers around pthread_mutex_t
 */

struct mutex {
    pthread_mutex_t mutex;
    char const *name;
};

void mutex_lock(struct mutex *);
void mutex_unlock(struct mutex *);
/// Grab the two mutexes, first the one with smaller address.
/** Useful to avoid some deadlocks. */
void mutex_lock2(struct mutex *restrict, struct mutex *restrict);
void mutex_unlock2(struct mutex *restrict, struct mutex *restrict);
void mutex_ctor(struct mutex *, char const *name);
void mutex_ctor_with_type(struct mutex *, char const *, int);
void mutex_dtor(struct mutex *);

/// A supermutex is a mutex wich allow recursive lock _and_ deadlock detection (through timedlock)
struct supermutex {
    struct mutex mutex;
    pthread_rwlock_t metalock;
    int rec_count;  ///< Recursive count (1 when the supermutex is locked once, 2 when the same thread relocked it, and so on)
    pthread_t owner; ///< The owner of the lock (if rec_count > 0)
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

#endif
