// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef REF_H_110324
#define REF_H_110324
#include <assert.h>
#include <junkie/config.h>
#include <junkie/tools/queue.h>
#include <junkie/tools/mutex.h>

/** @file
 * @brief Reference counted objects
 *
 * Some objects are ref-counted since they can be used by several other objects
 * and so their lifespan is unpredictable.
 * But as these objects are used concurrently by several threads running amok,
 * we have to take extra provisions :
 *
 * - first we inc/dec the count atomically (using a mutex in case atomic
 * operations are not readily available)
 *
 * - then we prevent a thread to delete an object which count reaches 0, since
 * this object address may be known by another thread that is about to inc the
 * count.  Refcounted object deletions are thus delayed until a safe point in
 * the program where all threads meet together without any pointer to any
 * refcounted object. As a consequence, it is not impossible for an object
 * count to be raised from 0 to 1.
 *
 * Note: ref counters gives you the assurance that a refed object won't
 * disapear, but does not prevent in any way another thread than yours to
 * modify it concurrently. */

struct ref {
    unsigned count;             ///< The count itself
#   define NOT_IN_DEATH_ROW ((void *)1)
    SLIST_ENTRY(ref) entry;     ///< If already on the death row, or NOT_IN_DEATH_ROW
#   ifndef __GNUC__
    struct mutex mutex;         ///< In dire circumstances when we can't use atomic operations
#   endif
    void (*del)(struct ref *);  ///< The delete function to finally get rid of the object
};

static inline void ref_ctor(struct ref *ref, void (*del)(struct ref *))
{
    ref->count = 1; // for the caller
    ref->entry.sle_next = NOT_IN_DEATH_ROW;
    ref->del = del;
#   ifndef __GNUC__
    mutex_ctor(&ref->mutex, "ref");
#   endif
}

static inline void ref_dtor(struct ref *ref)
{
    assert(ref->count == 0);
    // We do not remove it from the death_row since the whole list is trashed after the deletions
#   ifndef __GNUC__
    mutex_dtor(&ref->mutex);
#   endif
}

static inline void *ref(struct ref *ref)
{
    if (! ref) return NULL;

#   ifdef __GNUC__
    (void)__sync_fetch_and_add(&ref->count, 1);
#   else
    mutex_lock(&ref->mutex);
    ref->count ++;
    mutex_unlock(&ref->mutex);
#   endif

    return ref;
}

SLIST_HEAD(refs, ref) death_row;
struct mutex death_row_mutex;

static inline void *unref(struct ref *ref)
{
    if (! ref) return NULL;

#   ifdef __GNUC__
    unsigned const c = __sync_fetch_and_sub(&ref->count, 1);
    assert(c > 0);  // or where did this ref came from ?
    bool const unreachable = c == 1;
#   else
    mutex_lock(&ref->mutex);
    assert(ref->count > 0);
    ref->count --;
    bool const unreachable = ref->count == 0;
    mutex_unlock(&ref->mutex);
#   endif

    if (unreachable) {
        /* The thread that downs the count to 0 is responsible for queuing the object onto the death row.
         * But two threads may try to perform this at the same time for the same object !
         * (ex: thread 1 unref to 0, thread 2 ref from 0 to 1, then unref from 1 to 0, so queue the object,
         * then thread 1 is scheduled by and queue again the object onto the death row...)
         * To handle this we merely check for NOT_IN_DEATH_ROW. */
        mutex_lock(&death_row_mutex);
        if (ref->entry.sle_next == NOT_IN_DEATH_ROW) SLIST_INSERT_HEAD(&death_row, ref, entry);
        mutex_unlock(&death_row_mutex);
    }
    return NULL;
}

void enter_unsafe_region(void);
void enter_safe_region(void);

void ref_init(void);
void ref_fini(void);

#endif
