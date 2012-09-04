// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2012, SecurActive.
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
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <assert.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <inttypes.h>
#include <signal.h>
#include <assert.h>
#include <junkie/tools/log.h>
#include <junkie/tools/cli.h>
#include <junkie/tools/miscmacs.h>
#include <junkie/tools/ext.h>
#include <junkie/proto/deduplication.h>
#include <junkie/proto/cap.h>

LOG_CATEGORY_DEF(duplicogram);
#undef LOG_CAT
#define LOG_CAT duplicogram_log_category


static int64_t refresh_rate = 1000000;  // 1 sec
static unsigned last_bucket_width = 0;
static unsigned bucket_width = 0;  //  in usec. If unset (0), set to 100ms/columns
EXT_PARAM_RW(bucket_width, "duplicogram-bucket-width", uint, "Width of time interval (in usec) used to compute dups distribution");

static pthread_t display_pth; // only set if display_started
static bool display_started;

static void *display_thread(void *);
static int cli_set_refresh(char const *v)
{
    char *end;
    double d = strtod(v, &end);
    if (*end != '\0') {
        SLOG(LOG_CRIT, "Cannot parse interval: %s", v);
        return -1;
    }
    refresh_rate = d * 1000000.;

    // spawn display thread
    if (0 != pthread_create(&display_pth, NULL, display_thread, NULL)) {
        SLOG(LOG_CRIT, "Cannot spawn display thread");
    }

    return 0;
}

static struct cli_opt duplicogram_opts[] = {
    { { "interval",     "d" },  "seconds",  "update interval (default: no display)", CLI_CALL,     { .call = &cli_set_refresh } },
    { { "bucket-width", NULL }, "useconds", "distribution step for time interval",   CLI_SET_UINT, { .uint = &bucket_width } },
};

static uint64_t nb_nodups, nb_dups;
static uint64_t sz_nodups, sz_dups;
static unsigned nb_buckets;
static unsigned *dups;
static struct mutex dup_lock;   // protects dups (since it can be reallocated anytime)

static void dup_reset_locked(void)
{
    nb_nodups = nb_dups = 0;
    sz_nodups = sz_dups = 0;
    memset(dups, 0, nb_buckets * sizeof(*dups));
}

static void dup_reset(void)
{
    mutex_lock(&dup_lock);
    dup_reset_locked();
    mutex_unlock(&dup_lock);
}

// caller should own dup_lock
static void init(void)
{
    static bool inited;
    if (inited && bucket_width == last_bucket_width) return;
    inited = true;
    last_bucket_width = bucket_width;

    if (bucket_width == 0) {
        unsigned columns;
        get_window_size(&columns, NULL);
        bucket_width = CEIL_DIV(max_dup_delay, columns);
    }
    nb_buckets = CEIL_DIV(max_dup_delay, bucket_width);
    if (dups) free(dups);
    dups = malloc(nb_buckets * sizeof(*dups));
    assert(dups);
    dup_reset_locked();
}

static void cap_callback(struct proto_subscriber unused_ *s, struct proto_info const unused_ *last, size_t cap_len, uint8_t const unused_ *packet, struct timeval const unused_ *now)
{
    mutex_lock(&dup_lock);
    init();
    nb_nodups ++;
    sz_nodups += cap_len;
    mutex_unlock(&dup_lock);
}

static void dup_callback(struct proto_subscriber unused_ *s, struct proto_info const *last, size_t cap_len, uint8_t const unused_ *packet, struct timeval const unused_ *now)
{
    struct dedup_proto_info *dedup = DOWNCAST(last, info, dedup_proto_info);
    mutex_lock(&dup_lock);
    init();
    unsigned const b = MIN(nb_buckets-1, dedup->dt / bucket_width);
    nb_dups ++;
    sz_dups += cap_len;
    dups[b] ++;
    mutex_unlock(&dup_lock);
}

/*
 * Display thread
 */

static volatile sig_atomic_t quit;

static void display(void)
{
    printf("\x1B[1;1H\x1B[2J");

    printf("dusp:  %12"PRIu64"/%-12"PRIu64" (%6.2f%%)\n", nb_dups, nb_dups+nb_nodups, 100.*(double)nb_dups/(nb_dups+nb_nodups));
    printf("bytes: %12"PRIu64"/%-12"PRIu64" (%6.2f%%)\n", sz_dups, sz_dups+sz_nodups, 100.*(double)sz_dups/(sz_dups+sz_nodups));

    unsigned lines, columns;
    get_window_size(&columns, &lines);
    
    if (lines <= 4) return;

    mutex_lock(&dup_lock);
    if (! dups) {
        printf("no data yet\n");
        mutex_unlock(&dup_lock);
        return;
    }

    // look for max dups
    static unsigned dups_max = 0;
    unsigned cur_dups_max = 0;
    for (unsigned b = 0; b < nb_buckets; b++) {
        if (dups[b] > cur_dups_max) cur_dups_max = dups[b];
    }
    if (dups_max == 0) {
        dups_max = cur_dups_max;
    } else {
        if (cur_dups_max > dups_max) {
            dups_max = cur_dups_max;
        } else if (cur_dups_max < dups_max/2) {
            dups_max = cur_dups_max;
        }
    }

    unsigned prev_y_label = ~0U;
    unsigned no_y_tick = 0;
    for (unsigned y = lines - 4; y > 0; y--) {
        unsigned const y_label = ROUND_DIV(dups_max*y, lines-3);
        if (no_y_tick++ == 5 && y_label != prev_y_label) {
            printf("%5u|", y_label);
            prev_y_label = y_label;
            no_y_tick = 0;
        } else {
            printf("     |");
        }
        for (unsigned x = 0; x < columns-6; x++) {
            printf(dups[x] >= y_label ? "*":" ");
        }
        puts("");
    }

    // we are done with dups
    mutex_unlock(&dup_lock);

#   define X_TICK 16    // one tick every X_TICK chars (must be power of 2)
    printf("     ");
    unsigned x;
    for (x = 0; x < columns-7; x++) printf(x & (X_TICK-1) ? "-" : "+");
    printf(">\n     ");
    unsigned x_label = 0;
    for (x = 0; x < columns-7-X_TICK; x+=X_TICK, x_label += X_TICK*bucket_width) {
        if (x > 0) printf("           "); // X_TICK-5 spaces long
        printf("%-5u", x_label);
    }
    for (; x < columns-8; x++) printf(" ");
    printf("           us");  // X_TICK-5 spaces long

    fflush(stdout);
}

static void *display_thread(void unused_ *dummy)
{
    set_thread_name("duplicogram display");

    while (1) {
#       define SLEEP_CHUNK 100000U
        int64_t r;
        for (r = refresh_rate; !quit && r > SLEEP_CHUNK; r -= SLEEP_CHUNK) {
            usleep(SLEEP_CHUNK);
        }
        if (quit) break;
        usleep(r);
        display();
        // reset
        dup_reset();
    }

    return NULL;
}

/*
 * Extensions
 */

// Returns dups as a list of (dt . dups) points (dt in usecs, dups as ratio)
static struct ext_function sg_get_duplicogram;
static SCM g_get_duplicogram(void)
{
    SCM lst = SCM_EOL;
    uint64_t const nb_pkts = nb_nodups + nb_dups;

    scm_dynwind_begin(0);
    mutex_lock(&dup_lock);
    scm_dynwind_unwind_handler(pthread_mutex_unlock_, &dup_lock.mutex, SCM_F_WIND_EXPLICITLY);

    unsigned dt = bucket_width/2;
    for (unsigned x = 0; x < nb_buckets; x++, dt += bucket_width) {
        lst = scm_cons(
                scm_cons(scm_from_uint(dt),
                         scm_from_double(nb_pkts > 0 ? (double)dups[x] / nb_pkts : 0.)),
                lst);
    }

    dup_reset_locked();
    scm_dynwind_end();

    return lst;
}

/*
 * Init
 */

static struct proto_subscriber dup_subscription;
static struct proto_subscriber cap_subscription;

void on_load(void)
{
    log_category_duplicogram_init();
    ext_param_bucket_width_init();

    SLOG(LOG_INFO, "Duplicogram loaded");
    cli_register("Duplicogram plugin", duplicogram_opts, NB_ELEMS(duplicogram_opts));

    mutex_ctor(&dup_lock, "Duplicogram mutex");

    ext_function_ctor(&sg_get_duplicogram,
        "get-duplicogram", 0, 0, 0, g_get_duplicogram,
        "(get-duplicogram): fetch duplicogram data and reset internal state. Not for the casual user");

    dup_subscriber_ctor(&dup_subscription, dup_callback);
    proto_subscriber_ctor(&cap_subscription, proto_cap, cap_callback);
}

void on_unload(void)
{
    SLOG(LOG_INFO, "Duplicogram unloading");
    dup_subscriber_dtor(&dup_subscription);
    proto_subscriber_dtor(&cap_subscription, proto_cap);
    cli_unregister(duplicogram_opts);
    //mutex_dtor(&dup_lock); no since we can have some callbacks called even after we unsubscribed (in another thread)

    if (display_started) {
        quit = 1;
        pthread_join(display_pth, NULL);
    }

    ext_param_bucket_width_fini();
    log_category_duplicogram_fini();
}
