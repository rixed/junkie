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
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include <time.h>
#include "junkie/tools/timeval.h"
#include "junkie/tools/tempstr.h"
#include "junkie/tools/serialization.h"

struct timeval const timeval_unset = TIMEVAL_INITIALIZER;

extern inline bool timeval_is_set(struct timeval const *);

extern inline void timeval_reset(struct timeval *);

// @returns micro-seconds
int64_t timeval_sub(struct timeval const *restrict a, struct timeval const *restrict b)
{
    int64_t a_ms = timeval_2_usec(a);
    int64_t b_ms = timeval_2_usec(b);

    return a_ms - b_ms;
}

int64_t timeval_age(struct timeval const *tv)
{
    struct timeval now;
    timeval_set_now(&now);
    return timeval_sub(&now, tv);
}

extern inline uint64_t timeval_2_usec(struct timeval const *tv);
extern inline void usec_2_timeval(struct timeval *tv, uint64_t usec);
extern inline int timeval_cmp(struct timeval const *restrict a, struct timeval const *restrict b);
extern inline void timeval_add_usec(struct timeval *tv, int64_t usec);
extern inline void timeval_add_sec(struct timeval *tv, int32_t sec);
extern inline void timeval_sub_usec(struct timeval *tv, int64_t usec);
extern inline void timeval_sub_msec(struct timeval *tv, int64_t msec);
extern inline void timeval_sub_sec(struct timeval *tv, int32_t sec);
extern inline void timeval_set_min(struct timeval *restrict a, struct timeval const *restrict b);
extern inline void timeval_set_max(struct timeval *restrict a, struct timeval const *restrict b);

char const *timeval_2_str(struct timeval const *tv)
{
    if (! tv->tv_sec) return "unset";

    char *str = tempstr();
    int len = 0;
    if (tv->tv_sec) len += snprintf(str, TEMPSTR_SIZE, "%"PRIu32"s", (uint32_t)tv->tv_sec);
    if (tv->tv_usec) snprintf(str+len, TEMPSTR_SIZE-len, "%s%"PRIu32"us", len > 0 ? " ":"", (uint32_t)tv->tv_usec);
    return str;
}

void timeval_set_now(struct timeval *now)
{
#   ifdef HAVE_CLOCK_GETTIME
    struct timespec tp;
    clock_gettime(CLOCK_REALTIME, &tp);
    now->tv_sec = tp.tv_sec;
    now->tv_usec = tp.tv_nsec / 1000;
#   else
    gettimeofday(now, NULL);
#   endif
}

void timeval_serialize(struct timeval const *tv, uint8_t **buf)
{
    serialize_4(buf, tv->tv_sec);
    serialize_4(buf, tv->tv_usec);
}

void timeval_deserialize(struct timeval *tv, uint8_t const **buf)
{
    tv->tv_sec = deserialize_4(buf);
    tv->tv_usec = deserialize_4(buf);
}
