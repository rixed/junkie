// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#include <assert.h>
#include <junkie/tools/log.h>
#include "tools/timeval.c"

// Some timevals to play with
static struct timeval const tv_a = { .tv_sec = 1271662615, .tv_usec = 0 };   // Approx Mon Apr 19 09:30
static struct timeval const tv_b = { .tv_sec = 1271662615, .tv_usec = 10 };
static struct timeval const tv_c = { .tv_sec = 1271662614, .tv_usec = 10 };
static struct timeval const tv_d = { .tv_sec = 1271600000, .tv_usec = 3 };
static struct timeval const tv_unset = { .tv_sec = 0, .tv_usec = 0 };
#define MS 1000000LL

static void timeval_sub_check_(struct timeval const *a, struct timeval const *b, int64_t expected)
{
    int64_t s = timeval_sub(a, b);
    assert(s == expected);
}

static void timeval_sub_check(void)
{
    // Test zero
    timeval_sub_check_(&tv_a, &tv_a, 0);
    // Test some positive results
    timeval_sub_check_(&tv_b, &tv_a, 10);
    timeval_sub_check_(&tv_b, &tv_c, MS);
    timeval_sub_check_(&tv_a, &tv_c, MS - 10);
    timeval_sub_check_(&tv_a, &tv_d, 62615*MS - 3);

    // Test that a-b = -(b-a)
    timeval_sub_check_(&tv_a, &tv_b, -10);
    timeval_sub_check_(&tv_c, &tv_b, -MS);
    timeval_sub_check_(&tv_c, &tv_a, -(MS - 10));
    timeval_sub_check_(&tv_d, &tv_a, -(62615*MS - 3));
}

static void timeval_is_set_check(void)
{
    assert(! timeval_is_set(&tv_unset));
    assert(timeval_is_set(&tv_a));
}

static void timeval_cmp_check_(struct timeval const *a, struct timeval const *b, int expected)
{
    int c = timeval_cmp(a, b);
    assert(c == expected);
}

static void timeval_cmp_check(void)
{
    // Check for equality
    timeval_cmp_check_(&tv_a, &tv_a, 0);
    timeval_cmp_check_(&tv_b, &tv_b, 0);
    // Check for greater
    timeval_cmp_check_(&tv_b, &tv_a, 1);
    timeval_cmp_check_(&tv_b, &tv_c, 1);
    timeval_cmp_check_(&tv_a, &tv_c, 1);
    timeval_cmp_check_(&tv_a, &tv_d, 1);
    timeval_cmp_check_(&tv_b, &tv_d, 1);
    timeval_cmp_check_(&tv_c, &tv_d, 1);
    // Check a>b -> b<a
    timeval_cmp_check_(&tv_a, &tv_b, -1);
    timeval_cmp_check_(&tv_c, &tv_b, -1);
    timeval_cmp_check_(&tv_c, &tv_a, -1);
    timeval_cmp_check_(&tv_d, &tv_a, -1);
    timeval_cmp_check_(&tv_d, &tv_b, -1);
    timeval_cmp_check_(&tv_d, &tv_c, -1);
}

static void timeval_add_usec_check_(struct timeval *a, int64_t diff, struct timeval const *expected)
{
    timeval_add_usec(a, diff);
    assert(0 == timeval_cmp(a, expected));
}

static void timeval_add_usec_check(void)
{
    // Try to get tv_a
    timeval_add_usec_check_(&(struct timeval){ .tv_sec = 1271662614, .tv_usec = 0 }, MS, &tv_a);
    timeval_add_usec_check_(&(struct timeval){ .tv_sec = 1271662613, .tv_usec = 0 }, 2*MS, &tv_a);
    timeval_add_usec_check_(&(struct timeval){ .tv_sec = 1271662610, .tv_usec = 10 }, 5*MS - 10, &tv_a);
    // Try to get tv_b
    timeval_add_usec_check_(&(struct timeval){ .tv_sec = 1271662614, .tv_usec = 0 }, MS + 10, &tv_b);
    timeval_add_usec_check_(&(struct timeval){ .tv_sec = 1271662613, .tv_usec = 0 }, 2*MS + 10, &tv_b);
    timeval_add_usec_check_(&(struct timeval){ .tv_sec = 1271662610, .tv_usec = 10 }, 5*MS, &tv_b);
    // Same from above
    timeval_add_usec_check_(&(struct timeval){ .tv_sec = 1271662616, .tv_usec = 0 }, -MS, &tv_a);
    timeval_add_usec_check_(&(struct timeval){ .tv_sec = 1271662617, .tv_usec = 0 }, -2*MS, &tv_a);
    timeval_add_usec_check_(&(struct timeval){ .tv_sec = 1271662620, .tv_usec = 10 }, -5*MS - 10, &tv_a);
    timeval_add_usec_check_(&(struct timeval){ .tv_sec = 1271662616, .tv_usec = 20 }, -MS - 10, &tv_b);
    timeval_add_usec_check_(&(struct timeval){ .tv_sec = 1271662617, .tv_usec = 0 }, -2*MS + 10, &tv_b);
    timeval_add_usec_check_(&(struct timeval){ .tv_sec = 1271662620, .tv_usec = 10 }, -5*MS, &tv_b);
}

static void timeval_add_sec_check(void)
{
    struct timeval tv1 = { .tv_sec = 1271662614, .tv_usec = 666 };
    struct timeval tv2 = tv1;
    assert(0 == timeval_cmp(&tv1, &tv2));
    timeval_add_sec(&tv1, 3);
    timeval_add_usec(&tv2, 3*MS);
    assert(0 == timeval_cmp(&tv1, &tv2));
}

static void timeval_min_max_check(void)
{
    struct timeval tv1 = { .tv_sec = 1, .tv_usec = 0 };
    struct timeval tv2 = { .tv_sec = 2, .tv_usec = 0 };
    struct timeval tv3 = { .tv_sec = 3, .tv_usec = 0 };

    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    timeval_set_max(&tv, &tv1); assert(tv.tv_sec == 2);
    timeval_set_max(&tv, &tv2); assert(tv.tv_sec == 2);
    timeval_set_max(&tv, &tv3); assert(tv.tv_sec == 3);

    tv.tv_sec = 2; tv.tv_usec = 0;
    timeval_set_min(&tv, &tv3); assert(tv.tv_sec == 2);
    timeval_set_min(&tv, &tv2); assert(tv.tv_sec == 2);
    timeval_set_min(&tv, &tv1); assert(tv.tv_sec == 1);
}

int main(void)
{
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("timeval_check.log");

    timeval_sub_check();
    timeval_is_set_check();
    timeval_cmp_check();
    timeval_add_usec_check();
    timeval_add_sec_check();
    timeval_min_max_check();

    return EXIT_SUCCESS;
}
