// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef TIMEBOUND_H_130913
#define TIMEBOUND_H_130913
#include <time.h>
#include <junkie/config.h>
#include <junkie/tools/queue.h>
#include <junkie/tools/mutex.h>
#include <junkie/tools/timeval.h>

/** @file
 * @brief Objects that are destructed after some period of inactivity.
 *
 * Essentially, a timebound object queue is a pool of TAILQ_HEADs and mutexes,
 * sorted with least recently used object last, a deletor function and a
 * timeouter thread.
 *
 * The timeout is configurable via a parameter that's created from the name of
 * the timebound.
 *
 * Each timebound object is then nothing more than an entry in the TAILQ of
 * its pool.
 *
 * Note that we may insert a timebound object in anyone of the pool entry.
 * We use a mere round robin to keep entries evenly loaded.
 *
 * Also, instead of a thread per pool we'd rather have a single thread running
 * every seconds and scanning all pools according to it's own timeout value.
 */

struct timebound;

/** A pool of timebound objects, all with same deletor.
 * Note: this deletor is not allowed to delete other objects from the same pool
 *       (this would require a Nazim's device on the timeouter). */
struct timebound_pool {
    char const *name;
    unsigned const *timeout;            ///< So that it's easy to take this timeout from an ext_param
    void (*del)(struct timebound *);    ///< Deletor for timebound objects held here this pool
    LIST_ENTRY(timebound_pool) entry;   ///< One timebounder thread to rule them all
    unsigned next_bucket;               ///< Round robin affectation of object to buckets. Not protected bu lock, don't care
    struct timebound_bucket {
        struct mutex mutex;             ///< Protects this list
        TAILQ_HEAD(timebounds, timebound) list; ///< Least recently used first
    } buckets[CPU_MAX*2];
};

void timebound_pool_ctor(struct timebound_pool *, char const *name, unsigned const *timeout, void (*del)(struct timebound *));
void timebound_pool_dtor(struct timebound_pool *);

/** A timebound object is merely an entry in the object queue.  We need the
 * deletor of the object, which is then supposed to destruct us (but can also
 * deindex the object, destruct other part of it, and so on). */
struct timebound {
    TAILQ_ENTRY(timebound) entry;
    time_t last_used;                   ///< Not timeval to save space
    struct timebound_bucket *bucket;    ///< Backlink to find the relevant mutex
    bool monitored;                     ///< Set if this object is still in a bucket
};

void timebound_ctor(struct timebound *, struct timebound_pool *, struct timeval const *now);
void timebound_dtor(struct timebound *);

void timebound_touch(struct timebound *, struct timeval const *now);

void timebound_init(void);
void timebound_fini(void);

#endif
