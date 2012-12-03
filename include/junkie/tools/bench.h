// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef METRIC_H_121203
#define METRIC_H_121203
#include <inttypes.h>
#include <junkie/cpp.h>

/** @file
 * @brief Some utilities to time and count various events in order to benchmark
 * junkies internals.
 */

/** To time anything we need RDTSC */
static inline uint64_t rdtsc(void)
{
#   if defined(__GNUC__) && defined(__x86_64__)
    uint64_t x;
    __asm__ __volatile__("rdtsc" : "=A" (x));
    return x;
#   else
    return 0U;
#   endif
}

/** The simplest of all possible bench: a single event which we can trigger.
 */
struct bench_atomic_event {
    uint64_t count;
    char *name;
};

void bench_atomic_event_ctor(struct bench_atomic_event *e, char const *name);
void bench_atomic_event_dtor(struct bench_atomic_event *e);

static inline void bench_event_fire(struct bench_atomic_event *e)
{
#   ifdef __GNUC__
    __sync_fetch_and_add(&e->count, 1);
#   else
    e->count ++;    // bah!
#   endif
}

/** To record events that have a duration. */
struct bench_event {
    struct bench_atomic_event count;
    uint64_t tot_duration;
};

void bench_event_ctor(struct bench_event *e, char const *name);

void bench_event_dtor(struct bench_event *);

static inline uint64_t bench_event_start(void) { return rdtsc(); }

static inline void bench_event_stop(struct bench_event *e, uint64_t start)
{
    bench_event_fire(&e->count);
    uint64_t duration = rdtsc() - start;
#   ifdef __GNUC__
    __sync_fetch_and_add(&e->tot_duration, duration);
#   else
    e->tot_duration += duration;
#   endif
}

/** Init */

void bench_init(void);
void bench_fini(void);

#endif
