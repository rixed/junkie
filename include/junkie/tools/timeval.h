// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef TIMEVAL_H_100409
#define TIMEVAL_H_100409
#include <stdint.h>
#include <sys/time.h>
#include <stdbool.h>
#include <limits.h>

/** @file
 * @brief utilities for handling struct timeval
 */

/// Define a struct timeval
#define TIMEVAL_INITIALIZER { 0, 0 }
#define END_OF_TIME { LONG_MAX, LONG_MAX }

/// @return microseconds
int64_t timeval_sub(struct timeval const *restrict, struct timeval const *restrict);

int64_t timeval_age(struct timeval const *);

static inline bool timeval_is_set(struct timeval const *tv)
{
    return tv->tv_sec != 0;
}

// this one is unset
extern struct timeval const timeval_unset;

static inline void timeval_reset(struct timeval *tv)
{
    tv->tv_sec = 0;
}

static inline int timeval_cmp(struct timeval const *restrict a, struct timeval const *restrict b)
{
    if (a->tv_sec < b->tv_sec) return -1;
    else if (a->tv_sec > b->tv_sec) return 1;
    else if (a->tv_usec < b->tv_usec) return -1;
    else if (a->tv_usec > b->tv_usec) return 1;
    return 0;
}

static inline void usec_2_timeval(struct timeval *tv, uint64_t usec)
{
    tv->tv_sec  = usec / 1000000;
    tv->tv_usec = usec % 1000000;
}

static inline uint64_t timeval_2_usec(struct timeval const *tv)
{
    assert(timeval_is_set(tv));
    return (uint64_t)tv->tv_sec * 1000000 + tv->tv_usec;
}

static inline void timeval_add_usec(struct timeval *tv, int64_t usec)
{
    usec_2_timeval(tv, timeval_2_usec(tv) + usec);
}

static inline void timeval_add_sec(struct timeval *tv, int32_t sec)
{
    tv->tv_sec += sec;
}

static inline void timeval_sub_usec(struct timeval *tv, int64_t usec)
{
    usec_2_timeval(tv, timeval_2_usec(tv) - usec);
}

static inline void timeval_sub_msec(struct timeval *tv, int64_t msec)
{
    usec_2_timeval(tv, timeval_2_usec(tv) - 1000*msec);
}

static inline void timeval_sub_sec(struct timeval *tv, int32_t sec)
{
    tv->tv_sec -= sec;
}

char const *timeval_2_str(struct timeval const *);
void timeval_set_now(struct timeval *);

static inline void timeval_set_min(struct timeval *restrict a, struct timeval const *restrict b)
{
    if (timeval_cmp(a, b) > 0) *a = *b;
}

static inline void timeval_set_max(struct timeval *restrict a, struct timeval const *restrict b)
{
    if (timeval_cmp(a, b) < 0) *a = *b;
}

void timeval_serialize(struct timeval const *, uint8_t **);
void timeval_deserialize(struct timeval *, uint8_t const **);

#endif
