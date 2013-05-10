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
#include <assert.h>
#include <stdbool.h>
#include <termios.h>    // for key input
#include "junkie/cpp.h"
#include "junkie/proto/cap.h"
#include "junkie/proto/eth.h"
#include "junkie/proto/ip.h"
#include "junkie/proto/tcp.h"
#include "junkie/proto/udp.h"
#include "junkie/tools/hash.h"
#include "junkie/tools/cli.h"
#include "junkie/tools/objalloc.h"
#include "junkie/tools/timeval.h"
#include "junkie/tools/tempstr.h"

/*
 * Parameters
 */

static int64_t refresh_rate = 1000000;  // 1 sec
static unsigned nb_entries = 0;         // from nb_lines
static bool use_dev = true;             // key use device id
static bool use_vlan = true;            // key use vlan id
static bool use_mac_src = true;         // key use mac src addr
static bool use_mac_dst = true;         // key use mac dst addr
static bool use_mac_proto = true;       // key use mac proto
static bool use_ip_src = true;          // key use IP src addr
static bool use_ip_dst = true;          // key use IP dst addr
static bool use_ip_proto = true;        // key use IP proto
static bool use_ip_version = true;      // key use IP version
static bool use_port_src = true;        // key use source port
static bool use_port_dst = true;        // key use dest port
static bool use_proto_stack = true;     // key use protocol stack
static enum sort_by { PACKETS, VOLUME } sort_by = VOLUME;

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

static struct cli_opt nettop_opts[] = {
    { { "interval",     "d" },  "seconds", "update interval (default: 1)", CLI_CALL,     { .call = &cli_set_refresh } },
    { { "nb-entries",   "n" },  NEEDS_ARG, "number of entries to display (default: as many fit the screen)", CLI_SET_UINT, { .uint = &nb_entries } },
    { { "use-dev",      NULL }, NEEDS_ARG, "use network device in the key", CLI_SET_BOOL, { .boolean = &use_dev } },
    { { "use-vlan",     NULL }, NEEDS_ARG, "use VLAN id in the key", CLI_SET_BOOL, { .boolean = &use_vlan } },
    { { "use-src-mac",  NULL }, NEEDS_ARG, "use source MAC in the key", CLI_SET_BOOL, { .boolean = &use_mac_src } },
    { { "use-dst-mac",  NULL }, NEEDS_ARG, "use dest MAC in the key", CLI_SET_BOOL, { .boolean = &use_mac_dst } },
    { { "use-mac-proto",NULL }, NEEDS_ARG, "use MAC prot in the key", CLI_SET_BOOL, { .boolean = &use_mac_proto } },
    { { "use-src-ip",   NULL }, NEEDS_ARG, "use source IP in the key", CLI_SET_BOOL, { .boolean = &use_ip_src } },
    { { "use-dst-ip",   NULL }, NEEDS_ARG, "use dest IP in the key", CLI_SET_BOOL, { .boolean = &use_ip_dst } },
    { { "use-ip-proto", NULL }, NEEDS_ARG, "use IP proto in the key", CLI_SET_BOOL, { .boolean = &use_ip_proto } },
    { { "use-ip-version", NULL }, NEEDS_ARG, "use IP version in the key", CLI_SET_BOOL, { .boolean = &use_ip_version } },
    { { "use-src-port", NULL }, NEEDS_ARG, "use source IP in the key", CLI_SET_BOOL, { .boolean = &use_port_src } },
    { { "use-dst-port", NULL }, NEEDS_ARG, "use dest IP in the key", CLI_SET_BOOL, { .boolean = &use_port_dst } },
    { { "use-proto-stack", NULL }, NEEDS_ARG, "use detected protocol stack in the key", CLI_SET_BOOL, { .boolean = &use_proto_stack } },
    { { "sort-by",      "s" },  NEEDS_ARG, "packets|volume", CLI_SET_ENUM, { .uint = &sort_by } },
};

/*
 * Key
 */

struct nettop_key {
    // From Capture:
    int dev_id;         // or -1
    // From Ethernet:
    int vlan_id;        // or -1
    unsigned char mac_src[ETH_ADDR_LEN];    // or ""
    unsigned char mac_dst[ETH_ADDR_LEN];
    int mac_proto;      // or -1
    // From IP:
    struct ip_addr ip_src;  // or 0.0.0.0
    struct ip_addr ip_dst;
    int ip_proto;       // or -1
    int ip_version;     // or -1
    // From TCP/UDP:
    int port_src;       // or -1
    int port_dst;       // or -1
    // From whole stack:
    char stack[128];    // or ""
};

static size_t print_proto_stack(char *dst, size_t sz, struct proto_info const *last)
{
    // Write parrent first:
    size_t len = 0;
    if (last->parent) {
        len = print_proto_stack(dst, sz, last->parent);
        if (len > sz) return len;   // can't write more
    }
    dst += len;
    sz -= len;

    // Then our own:
    int l = snprintf(dst, sz, "%s%s", len ? "/":"", last->parser->proto->name);
    return len + l;
}

static void nettop_key_ctor(struct nettop_key *k, struct proto_info const *last)
{
    ASSIGN_INFO_OPT2(tcp, udp, last);
    struct proto_info const *l4 = tcp ? &tcp->info : udp ? &udp->info : NULL;
    struct port_key const *ports = tcp ? &tcp->key : udp ? &udp->key : NULL;
    ASSIGN_INFO_OPT2(ip, ip6, l4 ? l4:last);
    ip = ip ? ip:ip6;
    ASSIGN_INFO_OPT(eth, ip ? &ip->info:last);
    ASSIGN_INFO_OPT(cap, eth ? &eth->info:last);

    memset(k, 0, sizeof(*k));
    if (use_dev) k->dev_id = cap ? (int)cap->dev_id : -1;
    if (use_vlan) k->vlan_id = eth ? eth->vlan_id : -1;
    if (use_mac_src) snprintf((char *)k->mac_src, sizeof(k->mac_src), "%."STRIZE(ETH_ADDR_LEN)"s", eth ? (char const *)eth->addr[0]:"");
    if (use_mac_dst) snprintf((char *)k->mac_dst, sizeof(k->mac_dst), "%."STRIZE(ETH_ADDR_LEN)"s", eth ? (char const *)eth->addr[1]:"");
    if (use_mac_proto) k->mac_proto = eth ? (int)eth->protocol:-1;
    if (use_ip_src && ip) k->ip_src = ip->key.addr[0];
    if (use_ip_dst && ip) k->ip_dst = ip->key.addr[1];
    if (use_ip_proto) k->ip_proto = ip ? (int)ip->key.protocol:-1;
    if (use_ip_version) k->ip_version = ip ? (int)ip->version:-1;
    if (use_port_src) k->port_src = ports ? (int)ports->port[0]:-1;
    if (use_port_dst) k->port_dst = ports ? (int)ports->port[1]:-1;
    if (use_proto_stack) print_proto_stack(k->stack, sizeof(k->stack), last);
}

static char const *nettop_key_2_str(struct nettop_key const *k)
{
    char *s = tempstr();
    size_t const sz = TEMPSTR_SIZE;
    size_t o = 0;

    if (o < sz && use_dev) {
        o += k->dev_id == -1 ?
            snprintf(s+o, sz-o, "    ") :
            snprintf(s+o, sz-o, " %3d", k->dev_id);
    }
    if (o < sz && use_vlan) {
        o += k->vlan_id == -1 ?
            snprintf(s+o, sz-o, "     ") :
            snprintf(s+o, sz-o, " %4d", k->vlan_id);
    }
    if (o < sz && use_mac_src) {
        o += k->mac_src[0] == '\0' ?
            snprintf(s+o, sz-o, "                   ") :
            snprintf(s+o, sz-o, " %12s", eth_addr_2_str(k->mac_src));
    }
    bool mac_proto_needed = true;
    if (o < sz && use_ip_src && k->ip_src.family != 0 /* FIXME */) {
        o += snprintf(s+o, sz-o, " %s", ip_addr_2_str(&k->ip_src));
        mac_proto_needed = false;
    }
    if (o < sz && use_ip_proto && k->ip_proto != -1) {
        o += snprintf(s+o, sz-o, " %s", ip_proto_2_str(k->ip_proto));
        mac_proto_needed = false;
    }
    if (o < sz && use_ip_version && !use_ip_src && !use_ip_dst && k->ip_version != -1) {
        o += snprintf(s+o, sz-o, " %d", k->ip_version);
        mac_proto_needed = false;
    }
    if (o < sz && use_port_src && k->port_src != -1) {
        o += snprintf(s+o, sz-o, ":%d", k->port_src);
        mac_proto_needed = false;
    }

    if (o < sz && (use_mac_src||use_ip_src||use_port_src) && (use_mac_dst||use_ip_dst||use_port_dst)) {
        o += snprintf(s+o, sz-o, " -> ");
    }

    if (o < sz && use_mac_dst) {
        o += k->mac_dst[0] == '\0' ?
            snprintf(s+o, sz-o, "                   ") :
            snprintf(s+o, sz-o, " %12s", eth_addr_2_str(k->mac_dst));
    }
    if (o < sz && use_ip_dst && k->ip_dst.family != 0 /* FIXME */) {
        o += snprintf(s+o, sz-o, " %s", ip_addr_2_str(&k->ip_dst));
        mac_proto_needed = false;
    }
    if (o < sz && use_port_dst && k->port_dst != -1) {
        o += snprintf(s+o, sz-o, ":%d", k->port_dst);
        mac_proto_needed = false;
    }
    if (o < sz && use_mac_proto && mac_proto_needed && k->mac_proto != -1) {
        o += snprintf(s+o, sz-o, " %s", eth_proto_2_str(k->mac_proto));
    }
    if (o < sz && use_proto_stack && k->stack[0] != '\0') {
        o += snprintf(s+o, sz-o, " %s", k->stack);
    }

    return s+1; // skip first separator
}

/*
 * Hash of key -> count
 */

struct nettop_cell {
    HASH_ENTRY(nettop_cell) entry;
    struct nettop_key key;
    uint64_t volume;
    uint64_t packets;
};

static HASH_TABLE(nettop_cells, nettop_cell) nettop_cells;
static struct mutex cells_lock;

// Caller must own cells_lock
static void nettop_cell_ctor(struct nettop_cell *cell, struct nettop_key const *k)
{
    cell->key = *k;
    cell->volume = 0;
    cell->packets = 0;

    HASH_INSERT(&nettop_cells, cell, k, entry);
}

static struct nettop_cell *nettop_cell_new(struct nettop_key const *k)
{
    struct nettop_cell *cell = objalloc(sizeof(*cell), "nettop cells");
    if (! cell) return NULL;
    nettop_cell_ctor(cell, k);
    return cell;
}

static void nettop_cell_dtor(struct nettop_cell *cell)
{
    HASH_REMOVE(&nettop_cells, cell, entry);
}

static void nettop_cell_del(struct nettop_cell *cell)
{
    nettop_cell_dtor(cell);
    objfree(cell);
}

/*
 * Callback
 */

static uint64_t value(struct nettop_cell const *cell)
{
    return sort_by == PACKETS ? cell->packets : cell->volume;
}

static void nettop_cell_print(struct nettop_cell const *cell)
{
    printf("%10"PRIu64" %10"PRIu64" %s\n", cell->packets, cell->volume, nettop_key_2_str(&cell->key));
}

static int cell_cmp(void const *c1_, void const *c2_)
{
    struct nettop_cell const *c1 = c1_, *c2 = c2_;
    uint64_t v1 = value(c1), v2 = value(c2);

    if (v1 > v2) return -1;
    else if (v1 < v2) return 1;
    return 0;
}

static void try_display(struct timeval const *now)
{
    static struct timeval last_display;
    if (timeval_is_set(&last_display) && timeval_sub(now, &last_display) < refresh_rate) return;
    last_display = *now;

    unsigned nb_entries = nb_entries;
    if (! nb_entries) { // from nb_lines
        static unsigned nb_lines;
        if (! nb_lines) {
            unsigned columns;
            get_window_size(&columns, &nb_lines);
            if (nb_lines < 5) nb_lines = 25;    // probably get_window_size failed?
        }
        nb_entries = nb_lines - 5;
    }

    // look for nb_entries top hitters
    struct nettop_cell top[nb_entries];
    unsigned last_e = 0;
    unsigned min_e = UNSET;
    uint64_t min_value = 0;

    struct nettop_cell *cell, *tmp;
    HASH_FOREACH_SAFE(cell, &nettop_cells, entry, tmp) {
        uint64_t const new_value = value(cell);
        if (new_value > min_value) {
            // look for a free slot or min_value (note: free slots will be at the end of nettops)
            if (last_e < nb_entries) {
                min_e = last_e;
                top[last_e++] = *cell;
            } else {
                assert(min_e != UNSET);
                top[min_e] = *cell;
            }
            // reset the min
            min_value = new_value;  // probably
            for (unsigned e = 0; e < last_e; e++) {
                uint64_t const v = value(&top[e]);
                if (v < min_value) {
                    min_value = v;
                    min_e = e;
                }
            }
        }
        nettop_cell_del(cell);
    }

    // Sort top array
    qsort(top, last_e, sizeof(top[0]), cell_cmp);

    // Display the result
    printf("\x1B[1;1H\x1B[2J");
    printf("   Packets     Volume ");
    if (use_dev) printf("Dev ");
    if (use_vlan) printf("Vlan ");
    printf("Key\n");
    for (unsigned e = 0; e < last_e; e++) {
        nettop_cell_print(&top[e]);
    }
}

static void pkt_callback(struct proto_subscriber unused_ *s, struct proto_info const *last, size_t unused_ cap_len, uint8_t const unused_ *packet, struct timeval const *now)
{
    mutex_lock(&cells_lock);

    try_display(now);

    ASSIGN_INFO_CHK(cap, last, );

    struct nettop_key k;
    nettop_key_ctor(&k, last);
    
    struct nettop_cell *cell;
    HASH_LOOKUP(cell, &nettop_cells, &k, key, entry);
    if (! cell) {
        cell = nettop_cell_new(&k);
        if (! cell) goto quit;
    }

    cell->volume += cap->info.payload;
    cell->packets ++;
quit:
    mutex_unlock(&cells_lock);
}

static struct proto_subscriber subscription;
static struct termios termios_orig;
static pthread_t keyctrl_pth;
static volatile sig_atomic_t quit;

// read keys and change use flags
static void *keyctrl_thread(void unused_ *dummy)
{
    while (! quit) {
        unsigned char c;
        int r = read(0, &c, 1);
        if (r == 0) {
            SLOG(LOG_ERR, "Cannot read(stdin): end of file");
            return NULL;
        } else if (r < 1) {
            SLOG(LOG_ERR, "Cannot read(stdin): %s", strerror(errno));
            quit =  1;
            return NULL;
        }
        switch (c) {
            case 'I': use_dev ^= 1; break;
            case 'V': use_vlan ^= 1; break;
            case 's': use_ip_src ^= 1; break;
            case 'S': use_port_src ^= 1; break;
            case 'd': use_ip_dst ^= 1; break;
            case 'D': use_port_dst ^= 1; break;
            case 'm': use_mac_src ^= 1; break;
            case 'M': use_mac_dst ^= 1; break;
            case 'p': use_ip_proto ^= 1; break;
            case 'P': use_mac_proto ^= 1; break;
            case 'v': use_ip_version ^= 1; break;
            case 'n': use_proto_stack ^= 1; break;
            case '+': refresh_rate *= 2; break;
            case '-': refresh_rate = MAX(refresh_rate/2, 1000); break;
        }
    }

    return NULL;
}

void on_load(void)
{
    tcgetattr(0, &termios_orig);
    struct termios termios_new = termios_orig;
//    cfmakeraw(&termios_new);
    termios_new.c_lflag &= ~(ECHO | ICANON);    // Disable echo and make chars available immediately
    tcsetattr(0, TCSANOW, &termios_new);

    if (0 != pthread_create(&keyctrl_pth, NULL, keyctrl_thread, NULL)) {
        SLOG(LOG_CRIT, "Cannot spawn keyboard controler thread");
    }

    objalloc_init();
    hash_init();
    SLOG(LOG_INFO, "NetTop loaded");
    cli_register("NetTop plugin", nettop_opts, NB_ELEMS(nettop_opts));
    HASH_INIT(&nettop_cells, 30011, "nettop hitters");
    mutex_ctor(&cells_lock, "nettop lock");
    hook_subscriber_ctor(&pkt_hook, &subscription, pkt_callback);
}

void on_unload(void)
{
    SLOG(LOG_INFO, "NetTop unloading");

    quit = 1;
    (void)pthread_cancel(keyctrl_pth);
    (void)pthread_join(keyctrl_pth, NULL);

    tcsetattr(0, TCSANOW, &termios_orig);

    hook_subscriber_dtor(&pkt_hook, &subscription);
    HASH_DEINIT(&nettop_cells);
//    mutex_dtor(&cells_lock); nope since another thread may keep sending a few more packets
    cli_unregister(nettop_opts);
    hash_fini();
    objalloc_fini();
}
