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
#include <assert.h>
#include <math.h>
#include "junkie/tools/log.h"
#include "junkie/tools/cli.h"
#include "junkie/tools/miscmacs.h"
#include "junkie/tools/ext.h"
#include "junkie/tools/term.h"
#include "junkie/tools/hash.h"
#include "junkie/tools/ip_addr.h"
#include "junkie/tools/tempstr.h"
#include "junkie/proto/tcp.h"
#include "junkie/proto/udp.h"
#include "junkie/proto/ip.h"
#include "junkie/proto/cap.h"

LOG_CATEGORY_DEF(delayogram);
#undef LOG_CAT
#define LOG_CAT delayogram_log_category

// We choose arbitrarily that the key will be the socket, but a key selection screen
// a la nettop may be useful in some situations

static int64_t refresh_rate = 1000000;  // 1 sec
static unsigned cutoff_delay = 400000;    // 400ms max observed delay
static bool logarithmic = true; // Y scale

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

// Global stats
static uint64_t num_tot_packets, num_l4_packets, num_seen_packets;

// Histogram from delay to number of packets
static unsigned num_buckets;
static unsigned *buckets;

static struct mutex lock;   // protects both hash and histogram

static void histo_clear(unsigned num_buckets, unsigned *buckets)
{
    if (! buckets) return;

    for (unsigned b = 0; b < num_buckets; b++) {
        buckets[b] = 0;
    }
    num_tot_packets = num_l4_packets = num_seen_packets = 0;
}

static void histo_print(unsigned num_buckets, unsigned *buckets, unsigned lines, unsigned columns, unsigned bucket_width)
{
    if (! buckets) {
        printf("no data yet\n");
        return;
    }

    double bucketsf[num_buckets];
    for (unsigned b = 0; b < num_buckets; b++) {
        bucketsf[b] = logarithmic ? log10(buckets[b]) : buckets[b];
    }

    // look for max value
    static double val_max = 0;
    double cur_val_max = 0;
    for (unsigned b = 0; b < num_buckets; b++) {
        if (bucketsf[b] > cur_val_max) cur_val_max = bucketsf[b];
    }
    if (val_max == 0) {
        val_max = cur_val_max;
    } else {
        if (cur_val_max > val_max) {
            val_max = cur_val_max;
        } else if (cur_val_max < val_max/2) {   // amortize scale changes
            val_max = cur_val_max;
        }
    }
    SLOG(LOG_DEBUG, "Max value: %f", val_max);

    unsigned prev_y_label = ~0U;
    unsigned no_y_tick = 0;
    for (unsigned y = lines - 2; y > 0; y--) {
        double y_label = val_max*y / (lines - 2);
        if (logarithmic) y_label = pow(10, y_label);
        if (no_y_tick++ == 5 && y_label != prev_y_label) {
            printf("%6.0f|", y_label);
            prev_y_label = y_label;
            no_y_tick = 0;
        } else {
            printf("      |");
        }
        for (unsigned x = 0; x < columns-7; x++) {
            printf(buckets[x] >= y_label ? "*": no_y_tick==0 ? ".":" ");
        }
        puts("");
    }

#   define X_TICK 16    // one tick every X_TICK chars (must be power of 2)
    printf("      ");
    unsigned x;
    for (x = 0; x < columns-8; x++) printf(x & (X_TICK-1) ? "-" : "+");
    printf(">\n      ");
    unsigned x_label = 0;
    for (x = 0; x < columns-8-X_TICK; x+=X_TICK, x_label += X_TICK*bucket_width) {
        if (x > 0) printf("         "); // X_TICK-7 spaces long
        printf("%-7u", x_label);
    }
    for (; x < columns-9; x++) printf(" ");
    printf("        us");  // X_TICK-7 spaces long

    fflush(stdout);

    histo_clear(num_buckets, buckets);
}

// Hash from socket key to last packet timestamp
struct delay_cell {
    HASH_ENTRY(delay_cell) entry;
    struct delay_key {
        unsigned ip_proto;
        struct ip_addr addr[2]; // src, then dest (these are unidirectional)
        uint16_t ports[2];
    } key;
    struct timeval last_ts;
};

static HASH_TABLE(delay_cells, delay_cell) delay_cells;

// Caller must own cells_lock
static void delay_cell_ctor(struct delay_cell *cell, struct delay_key const *k, struct timeval const *now)
{
    cell->key = *k;
    cell->last_ts = *now;

    HASH_INSERT(&delay_cells, cell, k, entry);
}

static struct delay_cell *delay_cell_new(struct delay_key const *k, struct timeval const *now)
{
    struct delay_cell *cell = objalloc(sizeof(*cell), "delay cells");
    if (! cell) return NULL;
    delay_cell_ctor(cell, k, now);
    return cell;
}

static char const *delay_key_2_str(struct delay_key const *k)
{
    return tempstr_printf("%s %s:%"PRIu16" -> %s:%"PRIu16, ip_proto_2_str(k->ip_proto), ip_addr_2_str(k->addr+0), k->ports[0], ip_addr_2_str(k->addr+1), k->ports[1]);
}

static int delay_key_ctor(struct delay_key *k, struct proto_info const *last)
{
    ASSIGN_INFO_CHK2(tcp, udp, last, -1);
    struct proto_info const *l4 = tcp ? &tcp->info : &udp->info;
    struct port_key const *ports = tcp ? &tcp->key : &udp->key;
    ASSIGN_INFO_OPT2(ip, ip6, l4 ? l4:last);
    ip = ip ? ip:ip6;

    memset(k, 0, sizeof(*k));
    k->ip_proto = ip->key.protocol;
    for (unsigned p=0; p<2; p++) {
        k->addr[p] = ip->key.addr[p];
        k->ports[p] = ports->port[p];
    }

    SLOG(LOG_DEBUG, "New delay_key for %s", delay_key_2_str(k));

    return 0;
}

static bool display_help;

static void do_display_help()
{
    printf(
        TOPLEFT CLEAR
        BRIGHT "Help for Interactive Commands" NORMAL " - Delayogram v%s\n"
        "\n", version_string);
    printf(
        "You can use keys to change cutoff delay and refresh rate.\n"
        "Refresh rate is: " BRIGHT "%.2fs" NORMAL "\n"
        "\n"
        "  " BRIGHT "i" NORMAL "     Zoom in\n"
        "  " BRIGHT "o" NORMAL "     Zoom out\n"
        "  " BRIGHT "l" NORMAL "     Logarithmic Y scale\n"
        "\n"
        "  " BRIGHT "+/-" NORMAL "   Refresh rate twice faster/slower\n"
        "  " BRIGHT "h,H,?" NORMAL " this help screen\n"
        "  " BRIGHT "q" NORMAL "     return to main screen\n"
        "  " BRIGHT "q,^C" NORMAL "  quit\n",
        refresh_rate/1000000.);
}

static void do_display(struct timeval const *now)
{
    if (! refresh_rate) return;

    printf(TOPLEFT CLEAR);
    printf("Delayogram - Every " BRIGHT "%.2fs%s" NORMAL " - " BRIGHT "%s" NORMAL, refresh_rate / 1000000., logarithmic ? " (logaritmic)":"", ctime(&now->tv_sec));
    printf("packets displayed/displayable/total: %"PRIu64"/%"PRIu64"/%"PRIu64"\n", num_seen_packets, num_l4_packets, num_tot_packets);

    unsigned lines, columns;
    get_window_size(&columns, &lines);

    if (lines <= 5 || !buckets) return;

    unsigned const bucket_width = ROUND_DIV(cutoff_delay, num_buckets);
    histo_print(num_buckets, buckets, lines-3, columns, bucket_width);
}

static struct timeval last_display;

static void try_display(struct timeval const *now)
{
    if (timeval_is_set(&last_display) && timeval_sub(now, &last_display) < refresh_rate) return;
    last_display = *now;

    do_display(now);
}

static void pkt_callback(struct proto_subscriber unused_ *s, struct proto_info const *last, size_t unused_ cap_len, uint8_t const unused_ *packet, struct timeval const *now)
{
    SLOG(LOG_DEBUG, "New packet at %s", timeval_2_str(now));

    num_tot_packets ++;

    ASSIGN_INFO_CHK(cap, last, );
    struct delay_key k;
    if (0 != delay_key_ctor(&k, last)) return;

    mutex_lock(&lock);
    if (! display_help) try_display(now);

    struct delay_cell *cell;
    HASH_LOOKUP(cell, &delay_cells, &k, key, entry);
    if (! cell) {
        (void)delay_cell_new(&k, now);
    } else {
        SLOG(LOG_DEBUG, "Previous cell for key %s had ts=%s", delay_key_2_str(&k), timeval_2_str(&cell->last_ts));
        int64_t dt = timeval_sub(now, &cell->last_ts);
        cell->last_ts = *now;
        num_l4_packets ++;
        if (dt >= 0 && dt < cutoff_delay) {
            if (! buckets) {
                get_window_size(&num_buckets, NULL);
                buckets = calloc(num_buckets, sizeof(*buckets));
            }
            if (buckets) {
                unsigned const b = (dt * num_buckets) / cutoff_delay;
                if (b < num_buckets) {
                    SLOG(LOG_DEBUG, "One more sample in bucket %u", b);
                    if (buckets) buckets[b] ++;
                    num_seen_packets ++;
                }
            }
        }
    }

    mutex_unlock(&lock);
}

// Key handling function
static void handle_key(char c)
{
    switch (c) {
        case 'i':
            cutoff_delay /= 2;
            break;
        case 'o':
            cutoff_delay *= 2;
            break;
        case 'l': logarithmic ^= 1; break;
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
    if (display_help) do_display_help();
    else do_display(&last_display);
}

/*
 * Init
 */

static struct proto_subscriber pkt_subscription;

static struct cli_opt delayogram_opts[] = {
    { { "interval",     "d" },  "seconds", "update interval. Set to 0 to disable display (default: 1s)", CLI_CALL,     { .call = &cli_set_refresh } },
    { { "cutoff",       NULL }, "delay", "cutoff delay in us (default: 400000)", CLI_SET_UINT, { .uint = &cutoff_delay } },
    { { "logarithmic",  NULL }, "logarithmic", "use a logarithmic Y scale (recommanded)", CLI_SET_BOOL, { .boolean = &logarithmic } },
};

void on_load(void)
{
    log_category_delayogram_init();

    SLOG(LOG_INFO, "Delayogram loaded");

    term_init(&handle_key);
    objalloc_init();
    hash_init();

    cli_register("Delayogram plugin", delayogram_opts, NB_ELEMS(delayogram_opts));
    HASH_INIT(&delay_cells, 30011, "delay cells");

    mutex_ctor(&lock, "Delayogram mutex");

    hook_subscriber_ctor(&pkt_hook, &pkt_subscription, pkt_callback);
}

void on_unload(void)
{
    SLOG(LOG_INFO, "Delayogram unloading");

    hash_fini();
    objalloc_fini();
    term_fini();

    hook_subscriber_dtor(&pkt_hook, &pkt_subscription);
    cli_unregister(delayogram_opts);
    //mutex_dtor(&lock); no since we can have some callbacks called even after we unsubscribed (in another thread)
    HASH_DEINIT(&delay_cells);

    log_category_delayogram_fini();
}
