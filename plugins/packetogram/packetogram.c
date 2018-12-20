// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2018, SecurActive.
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
#include "junkie/proto/cap.h"
#include "junkie/cpp.h"
#include "junkie/tools/cli.h"
#include "junkie/tools/mutex.h"
#include "junkie/tools/term.h"
#include "junkie/tools/ext.h"   // for version_string

static int64_t refresh_rate = 1000000;  // 1 sec
static unsigned bucket_width = 50;  // 50 bytes = 1 bar
static bool display_help;

static int cli_set_refresh(char const *v)
{
    char *end;
    double d = strtod(v, &end);
    if (*end != '\0') {
        SLOG(LOG_CRIT, "Cannot parse interval: %s", v);
        return -1;
    }
    refresh_rate = d * 1000000.;
    return 0;
}

static struct cli_opt packetogram_opts[] = {
    { { "interval",     "d" },  "seconds", "update interval", CLI_CALL,     { .call = &cli_set_refresh } },
    { { "bucket-width", NULL }, "bytes",   "distribution step width for packet size",
                                                              CLI_SET_UINT, { .uint = &bucket_width } },
};

static struct mutex disp_lock;
static unsigned max_size = 0;
static unsigned min_size = UINT_MAX;
static unsigned max_count = 0;
static unsigned count = 0;
static unsigned histo[65536];
static unsigned proto_count[PROTO_CODE_MAX];
static unsigned nb_disps;
static unsigned histo_tot[65536];
static unsigned proto_tot[NB_ELEMS(proto_count)];

static int proto_code_cmp(void const *a_, void const *b_)
{
    enum proto_code const *a = a_;
    enum proto_code const *b = b_;
    if (proto_tot[*a] < proto_tot[*b]) return -1;
    else if (proto_tot[*a] == proto_tot[*b]) return 0;
    return 1;
}

static void do_display_help(void)
{
    printf(
        TOPLEFT CLEAR
        BRIGHT "Help for Interactive Commands" NORMAL " - Packetogram v%s\n"
        "\n", version_string);
    printf(
        "Refresh rate is: " BRIGHT "%.2fs" NORMAL "\n"
        "\n"
        "  " BRIGHT "+/-" NORMAL "   Refresh rate twice faster/slower\n"
        "  " BRIGHT "h,H,?" NORMAL " this help screen\n"
        "  " BRIGHT "q" NORMAL "     return to main screen\n"
        "  " BRIGHT "q,^C" NORMAL "  quit\n",
        refresh_rate/1000000.);
}

static void do_display(struct timeval const *now)
{
    static unsigned tot_min_size = UINT_MAX;
    if (min_size < tot_min_size) tot_min_size = min_size;
    static unsigned tot_max_size = 0;
    if (max_size > tot_max_size) tot_max_size = max_size;
    static unsigned tot_max_count = 0;
    if (max_count > tot_max_count) tot_max_count = max_count;
    static uint64_t tot_count = 0;
    tot_count += count;

    unsigned const max_bucket = tot_max_size / bucket_width;

    // total count for grand average
    bool rescale = false;
    for (unsigned s = 0; s <= max_bucket; s ++) {
        histo_tot[s] += histo[s];
        if (histo_tot[s] >= (UINT_MAX>>1)) rescale = true;
    }
    for (unsigned p = 0; p < NB_ELEMS(proto_count); p++) {
        proto_tot[p] += proto_count[p];
        if (proto_tot[p]  >= (UINT_MAX>>1)) rescale = true;
    }
    nb_disps ++;
    if (rescale) {
        for (unsigned s = 0; s <= max_bucket; s ++) histo_tot[s] >>= 1;
        for (unsigned p = 0; p < NB_ELEMS(proto_count); p++) proto_tot[p] >>= 1;
        nb_disps >>= 1;
    }

    /* Display protocol statistics */

    printf(TOPLEFT CLEAR);
    printf("Packetogram - Every " BRIGHT "%.2fs" NORMAL " - " BRIGHT "%s" NORMAL, refresh_rate / 1000000., ctime(&now->tv_sec));

    unsigned nb_pc = 0;
    enum proto_code pc[NB_ELEMS(proto_count)];
    struct proto *proto;
    LIST_FOREACH(proto, &protos, entry) {
        if (proto_count[proto->code] == 0 && proto_tot[proto->code] == 0) continue;
        pc[nb_pc++] = proto->code;
    }
    qsort(pc, nb_pc, sizeof(pc[0]), proto_code_cmp);

    /* Display distribution of sizes */

    unsigned lineno = 1;
    unsigned lines, columns;
    get_window_size(&columns, &lines);

    // Y scale : max_bucket buckets in lines-lineno-1 lines
    unsigned nb_buckets_per_line = 1;
    if (lines-lineno > 1 && max_bucket > lines-lineno-1) {
        nb_buckets_per_line = (max_bucket+lines-lineno-1-1) / (lines-lineno-1);
    }
    assert(nb_buckets_per_line >= 1);

    for (unsigned s = 0; s <= max_bucket || nb_pc > 0; ) {
        if (nb_pc > 0) {
            nb_pc--;
            proto = proto_of_code(pc[nb_pc]);
            printf("%11s: %6u/%-7u (%5.1f%%) ",
                proto->name,
                proto_count[proto->code],
                proto_tot[proto->code],
                (100. * proto_tot[proto->code])/tot_count);
        } else {
            printf("                                     ");
        }

        if (s <= max_bucket) {
            unsigned n = 0, t = 0;
            for (unsigned b = 0; b < nb_buckets_per_line; b++) {
                n += histo[s+b];
                t += histo_tot[s+b];
            }
#           define LABEL_WIDTH (38+27)
            unsigned const bar_size = columns > LABEL_WIDTH && tot_max_count > 0 ?
                (n * (columns - LABEL_WIDTH)) / (tot_max_count * nb_buckets_per_line) : 0;
            assert(bar_size <= columns - LABEL_WIDTH);
            unsigned const avg_size = columns > LABEL_WIDTH && tot_max_count > 0 && nb_disps > 0 ?
                (((t + nb_disps-1) / nb_disps) * (columns - LABEL_WIDTH)) / (tot_max_count * nb_buckets_per_line) : 0;
            assert(avg_size <= columns - LABEL_WIDTH);
            float const percent = count > 0 ? n * 100. / count : 0.;
            printf("%5u-%5u: %5u, %5.1f%% ", s*bucket_width, (s+nb_buckets_per_line)*bucket_width-1, n, percent);
            unsigned c;
            for (c = 0; c < bar_size; c ++) {
                printf(c == avg_size-1 ? "+":"-");
            }
            for (; avg_size > 0 && c < avg_size-1; c++) printf(" ");
            if (c == avg_size-1) printf("|");
            s += nb_buckets_per_line;
        }
        puts("");

        if (++lineno >= lines-2) break;
    }
#   define DISP(x) ((x) < UINT_MAX ? (x) : 0)
    printf("                                    "
           "      count: %5u/%5"PRIu64", min size: %5u/%5u, max size: %5u/%5u\n",
            count, tot_count,
            DISP(min_size), DISP(tot_min_size),
            DISP(max_size), DISP(tot_max_size));
}

static struct timeval last_display;

static void try_display(struct timeval const *now)
{
    if (timeval_is_set(&last_display) && timeval_sub(now, &last_display) < refresh_rate) return;
    last_display = *now;

    mutex_lock(&disp_lock);
    do_display(now);
    // reset
    unsigned const max_bucket = max_size / bucket_width;
    memset(histo, 0, sizeof(histo[0]) * (max_bucket+1));
    memset(proto_count, 0, sizeof(proto_count));
    max_size = max_count = count = 0;
    min_size = UINT_MAX;
    mutex_unlock(&disp_lock);
}

static void pkt_callback(struct proto_subscriber unused_ *s, struct proto_info const *last, size_t unused_ cap_len, uint8_t const unused_ *packet, struct timeval const *now)
{
    if (! display_help) try_display(now);

    struct proto_info const *info = last;
    while (info->parent) {
        proto_count[info->parser->proto->code] ++;
        info = info->parent;
    }
    assert(info->parser->proto == proto_cap);
    struct cap_proto_info const *cap = DOWNCAST(info, info, cap_proto_info);

    unsigned const size = cap->info.payload;
    unsigned const bucket = size / bucket_width;
    assert(bucket < NB_ELEMS(histo));

    mutex_lock(&disp_lock);
    count ++;
    histo[bucket] ++;
    if (size > max_size) max_size = size;
    if (size < min_size) min_size = size;
    if (histo[bucket] > max_count) max_count = histo[bucket];
    mutex_unlock(&disp_lock);
}

// Key handling function
static void handle_key(char c)
{
    switch (c) {
        case '+': refresh_rate *= 2; break;
        case '-': refresh_rate = MAX(refresh_rate/2, 1000); break;
        case '?':
        case 'h':
        case 'H': display_help ^= 1; break;
        case 'q':
            if (display_help) {
                display_help = false;
            } else {
                term_fini();
                _exit(0);
            }
            break;
        case '\n':
            if (display_help) {
                display_help = false;
            }
            break;
    }
    mutex_lock(&disp_lock);
    if (display_help) do_display_help();
    else do_display(&last_display);
    mutex_unlock(&disp_lock);
}

/*
 * Init
 */

static struct proto_subscriber subscription;

void on_load(void)
{
    SLOG(LOG_INFO, "Packetogram loaded");
    term_init(&handle_key);
    cli_register("Packetogram plugin", packetogram_opts, NB_ELEMS(packetogram_opts));

    mutex_ctor(&disp_lock, "display lock");

    hook_subscriber_ctor(&pkt_hook, &subscription, pkt_callback);
}

void on_unload(void)
{
    SLOG(LOG_INFO, "Packetogram unloading");

    term_fini();

    hook_subscriber_dtor(&pkt_hook, &subscription);
    cli_unregister(packetogram_opts);

    mutex_dtor(&disp_lock);
}

