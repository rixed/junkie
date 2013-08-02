// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef METRIC_H_121203
#define METRIC_H_121203
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <junkie/config.h>
#include <junkie/cpp.h>

/** @file
 * @brief Some utilities to time and count various events in order to benchmark
 * junkies internals.
 */

/** To time anything we need RDTSC */
#ifdef WITH_BENCH
static inline uint64_t rdtsc(void)
{
#   if defined(__GNUC__) && defined(__x86_64__)
        uint32_t hi, lo;
        __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
        return (((uint64_t)hi)<<32U) | lo;
#   elif defined(__GNUC__) && defined(__i386__)
        uint64_t x;
        __asm__ __volatile__("rdtsc" : "=A" (x));
        return x;
#   else
#       warning No rdtsc no bench
        return 0U;
#   endif
}
#else
#   define rdtsc() (0U)
#endif


/** The simplest of all possible bench: a single event which we can trigger.
 */
struct bench_atomic_event {
#   ifdef WITH_BENCH
    uint64_t count;
    char *name;
    bool name_malloced;
#   endif
};

void bench_atomic_event_ctor(struct bench_atomic_event *e, char const *name);
void bench_atomic_event_dtor(struct bench_atomic_event *e);

// Or use this for static initialization:
#ifdef WITH_BENCH
#   define BENCH_ATOMIC(n) { .count = 0, .name = (n), .name_malloced = false }
#else
#   define BENCH_ATOMIC(n) {}
#endif

#ifdef WITH_BENCH
static inline void bench_event_fire(struct bench_atomic_event *e)
{
#   ifdef __GNUC__
    __sync_fetch_and_add(&e->count, 1);
#   else
    e->count ++;    // bah!
#   endif
}
#else
#   define bench_event_fire(e) ((void)e)
#endif

/** To record events that have a duration. */
struct bench_event {
#   ifdef WITH_BENCH
    struct bench_atomic_event count;
    uint64_t tot_duration, min_duration, max_duration;
#   endif
};

void bench_event_ctor(struct bench_event *e, char const *name);

// Or use this for static initialization:
#ifdef WITH_BENCH
#   define BENCH(n) { .count = BENCH_ATOMIC(n), .tot_duration = 0, .min_duration = UINT64_MAX, .max_duration = 0, }
#else
#   define BENCH(n) {}
#endif

void bench_event_dtor(struct bench_event *);

#ifdef WITH_BENCH
static inline uint64_t bench_event_start(void) { return rdtsc(); }
#else
#   define bench_event_start() (0U)
#endif

#ifdef WITH_BENCH
static inline void bench_event_stop(struct bench_event *e, uint64_t start)
{
    bench_event_fire(&e->count);
    uint64_t duration = rdtsc() - start;
#   ifdef __GNUC__
    __sync_fetch_and_add(&e->tot_duration, duration);
#   else
    e->tot_duration += duration;
#   endif
    // min and max are approximate only
    if (duration < e->min_duration) e->min_duration = duration;
    if (duration > e->max_duration) e->max_duration = duration;
}
#else
#   define bench_event_stop(e, start) ((void)e, (void)start)
#endif

/** Init */

void bench_init(void);
void bench_fini(void);

#endif
