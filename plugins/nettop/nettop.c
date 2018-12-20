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
#include <assert.h>
#include <stdbool.h>
#include <signal.h>     // for sig_atomic_t
#include "junkie/cpp.h"
#include "junkie/proto/cap.h"
#include "junkie/proto/eth.h"
#include "junkie/proto/ip.h"
#include "junkie/proto/tcp.h"
#include "junkie/proto/udp.h"
#include "junkie/tools/proto_stack.h"
#include "junkie/tools/hash.h"
#include "junkie/tools/cli.h"
#include "junkie/tools/objalloc.h"
#include "junkie/tools/timeval.h"
#include "junkie/tools/tempstr.h"
#include "junkie/tools/term.h"

static bool display_help;

/*
 * Parameters
 */

static int64_t refresh_rate = 1000000;  // 1 sec
static unsigned nb_entries = 0;         // from nb_lines
static bool use_dev = false;            // key use device id
static bool use_vlan = false;           // key use vlan id
static bool use_mac_src = false;        // key use mac src addr
static bool use_mac_dst = false;        // key use mac dst addr
static bool use_mac_proto = true;       // key use mac proto
static bool use_ip_src = true;          // key use IP src addr
static bool use_ip_dst = true;          // key use IP dst addr
static bool use_ip_proto = true;        // key use IP proto
static bool use_ip_version = true;      // key use IP version
static bool use_port_src = true;        // key use source port
static bool use_port_dst = true;        // key use dest port
static bool use_proto_stack = true;     // key use protocol stack
static enum sort_by { PACKETS, VOLUME } sort_by = VOLUME;
static bool shorten_proto_stack = true; // display only the last component
static bool bidirectional = false;      // whether or not src/dst fields must be reordered before counting

static char const *current_key_2_str(void)
{
    char *s = tempstr_printf("%s%s%s%s%s%s%s%s%s%s%s%s%s",
        use_dev ? ", device id":"",
        use_vlan ? ", VLAM id":"",
        use_ip_src ? ", src IP":"",
        use_port_src ? ", src port":"",
        use_mac_src ? ", src MAC":"",
        use_ip_dst ? ", dest IP":"",
        use_port_dst ? ", dest port":"",
        use_mac_dst ? ", dest MAC":"",
        use_mac_proto ? ", Ethernet protocol":"",
        use_ip_proto ? ", IP protocol":"",
        use_ip_version ? ", IP version":"",
        use_proto_stack ? ", protocol names":"",
        use_proto_stack && shorten_proto_stack ? " (short)":""
    );
    if (s[0] == ',') s++;
    return s;
}

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
    { { "bidirectional", NULL }, NEEDS_ARG, "bidirectional", CLI_SET_BOOL, { .boolean = &bidirectional } },
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
    struct proto_stack stack;
};

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
    unsigned min = 0;
    if (bidirectional) min = memcmp(eth->addr+0, eth->addr+1, ETH_ADDR_LEN) <= 0 ? 0:1;
    if (use_mac_src && eth) memcpy(k->mac_src, eth->addr[ min], ETH_ADDR_LEN);
    if (use_mac_dst && eth) memcpy(k->mac_dst, eth->addr[!min], ETH_ADDR_LEN);
    if (use_mac_proto) k->mac_proto = eth ? (int)eth->protocol:-1;
    if (use_ip_src && ip) k->ip_src = ip->key.addr[ min];
    if (use_ip_dst && ip) k->ip_dst = ip->key.addr[!min];
    if (use_ip_proto) k->ip_proto = ip ? (int)ip->key.protocol:-1;
    if (use_ip_version) k->ip_version = ip ? (int)ip->version:-1;
    if (use_port_src) k->port_src = ports ? (int)ports->port[ min]:-1;
    if (use_port_dst) k->port_dst = ports ? (int)ports->port[!min]:-1;
    if (use_proto_stack) (void)proto_stack_update(&k->stack, last);
}

static char const *nettop_key_2_str(struct nettop_key const *k, unsigned proto_len, unsigned addr_len)
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

    // Protocol
    bool mac_proto_needed = true;
    bool ip_proto_needed = true;
    char proto_str[proto_len];
    proto_str[0] = '\0';
    size_t proto_o = 0;

    if (proto_o < proto_len && use_proto_stack && k->stack.depth > 0) {
        char const *stack = k->stack.name;
        if (shorten_proto_stack) {
            char *c = strrchr(k->stack.name, '/');
            if (c) stack = c+1;
        }
        proto_o += snprintf(proto_str+proto_o, proto_len-proto_o, " %s", stack);
        while (use_ip_proto && k->ip_proto != -1) {
            char const *proto = ip_proto_2_str(k->ip_proto);
            char *f = strstr(k->stack.name, proto);
            if (! f) break;  // name not found
            if (f != k->stack.name && f[-1] != '/') break;   // not at beginning of proto name
            int l = strlen(proto);
            if (f[l] != '\0' && f[l] != '/') break; // not at end of proto name
            // let's face it: we already print the IP proto name
            ip_proto_needed = false;
            break;
        }
    }
    if (proto_o < proto_len && use_ip_proto && ip_proto_needed && k->ip_proto != -1) {
        proto_o += snprintf(proto_str+proto_o, proto_len-proto_o, " %s", ip_proto_2_str(k->ip_proto));
        mac_proto_needed = false;
    }
    if (proto_o < proto_len && use_ip_version && !use_ip_src && !use_ip_dst && k->ip_version != -1) {
        proto_o += snprintf(proto_str+proto_o, proto_len-proto_o, " %d", k->ip_version);
        mac_proto_needed = false;
    }

    // Source
    size_t src_len = addr_len;
    char src_str[src_len];
    src_str[0] = '\0';
    size_t src_o = 0;

    if (src_o < src_len && use_mac_src) {
        src_o += snprintf(src_str+src_o, src_len-src_o, " %s", eth_addr_2_str(k->mac_src));
    }
    if (src_o < src_len && use_ip_src && k->ip_src.family != 0 /* FIXME */) {
        src_o += snprintf(src_str+src_o, src_len-src_o, " %s", ip_addr_2_str(&k->ip_src));
        mac_proto_needed = false;
    }
    if (src_o < src_len && use_port_src && k->port_src != -1) {
        src_o += snprintf(src_str+src_o, src_len-src_o, ":%d", k->port_src);
        mac_proto_needed = false;
    }

    if (proto_o < proto_len && use_mac_proto && mac_proto_needed && k->mac_proto != -1) {
        proto_o += snprintf(proto_str+proto_o, proto_len-proto_o, " %s", eth_proto_2_str(k->mac_proto));
    }

    // Dest
    size_t dst_len = addr_len;
    char dst_str[dst_len];
    dst_str[0] = '\0';
    size_t dst_o = 0;

    if (dst_o < dst_len && use_mac_dst) {
        dst_o += snprintf(dst_str+dst_o, dst_len-dst_o, " %s", eth_addr_2_str(k->mac_dst));
    }
    if (dst_o < dst_len && use_ip_dst && k->ip_dst.family != 0 /* FIXME */) {
        dst_o += snprintf(dst_str+dst_o, dst_len-dst_o, " %s", ip_addr_2_str(&k->ip_dst));
        mac_proto_needed = false;
    }
    if (dst_o < dst_len && use_port_dst && k->port_dst != -1) {
        dst_o += snprintf(dst_str+dst_o, dst_len-dst_o, ":%d", k->port_dst);
        mac_proto_needed = false;
    }

    char const *bidir = bidirectional ? " <->":" ->";
    if (o < sz) o += snprintf(s+o, sz-o, "%*s %*s%s%-*s", (int)proto_len, proto_str, (int)src_len, src_str, src_str[0]!='\0' && dst_str[0]!='\0' ? bidir:"", (int)dst_len, dst_str);
    return s;
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
 * Display
 */

static uint_least64_t packets_count, bytes_count;
static struct timeval start_counting;

static uint64_t value(struct nettop_cell const *cell)
{
    return sort_by == PACKETS ? cell->packets : cell->volume;
}

static void nettop_cell_print(struct nettop_cell const *cell, unsigned proto_len, unsigned addr_len)
{
    if (sort_by == PACKETS) {
        printf(BRIGHT "%10"PRIu64 NORMAL " %10"PRIu64, cell->packets, cell->volume);
    } else {
        printf("%10"PRIu64 BRIGHT " %10"PRIu64 NORMAL, cell->packets, cell->volume);
    }

    printf(" %s\n", nettop_key_2_str(&cell->key, proto_len, addr_len));
}

static int cell_cmp(void const *c1_, void const *c2_)
{
    struct nettop_cell const *c1 = c1_, *c2 = c2_;
    uint64_t v1 = value(c1), v2 = value(c2);

    if (v1 > v2) return -1;
    else if (v1 < v2) return 1;
    return 0;
}

static void do_display_top(struct timeval const *now)
{
    unsigned nb_lines, nb_columns;
    get_window_size(&nb_columns, &nb_lines);
    if (nb_lines < 5) nb_lines = 25;    // probably get_window_size failed?

    unsigned nbe = nb_entries;
    if (! nb_entries) { // from nb_lines
        nbe = nb_lines - 5;
    }

    // look for nbe top hitters
    struct nettop_cell top[nbe];
    unsigned last_e = 0;
    unsigned min_e = UNSET;
    uint64_t min_value = 0;

    struct nettop_cell *cell, *tmp;
    HASH_FOREACH_SAFE(cell, &nettop_cells, entry, tmp) {
        uint64_t const new_value = value(cell);
        if (new_value > min_value) {
            // look for a free slot or min_value (note: free slots will be at the end of nettops)
            if (last_e < nbe) {
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
    printf(TOPLEFT CLEAR);
    printf("NetTop - Every " BRIGHT "%.2fs" NORMAL " - " BRIGHT "%s" NORMAL, refresh_rate / 1000000., ctime(&now->tv_sec));
    printf("Packets: " BRIGHT "%"PRIu64 NORMAL", Bytes: " BRIGHT "%"PRIu64 NORMAL,
        packets_count, bytes_count);
    int64_t const dt = (timeval_sub(now, &start_counting) + 500000) / 1000000;
    if (dt >= 1) {
        printf(" (%"PRIu64" bytes/sec)", bytes_count / dt);
    }
    printf("\n\n");
    packets_count = 0; bytes_count = 0;
    start_counting = *now;

    unsigned const proto_len = 10 + (use_proto_stack && !shorten_proto_stack ? 30:0);
    unsigned const addrs_len = nb_columns - 23 - proto_len - (use_vlan ? 5:0) - (use_dev ? 5:0) - (bidirectional ? 1:0);
    unsigned const addr_len = (addrs_len - 3) / 2;
    unsigned c = 0;
    printf(REVERSE);
    c += printf("   Packets     Volume ");
    if (use_dev) c += printf("Dev ");
    if (use_vlan) c += printf("Vlan ");
    c += printf("%*s", proto_len, "Protocol");
    c += printf("%*s", addr_len+1, "Source");
    c += printf("   ");
    c += printf("%-*s", addr_len, " Destination");
    for (; c < nb_columns; c++) printf(" ");
    printf(NORMAL "\n");
    for (unsigned e = 0; e < last_e; e++) {
        nettop_cell_print(&top[e], proto_len, addr_len);
    }
}

static struct timeval last_display;

static void try_display(struct timeval const *now)
{
    if (timeval_is_set(&last_display) && timeval_sub(now, &last_display) < refresh_rate) return;
    last_display = *now;

    do_display_top(now);
}

static void do_display_help(void)
{
    printf(
        TOPLEFT CLEAR
        BRIGHT "Help for Interactive Commands" NORMAL " - NetTop v%s\n"
        "\n", version_string);
    printf(
        "Most keys control what fields are used to group traffic.\n"
        "Currently, packets are grouped by:\n"
        "   " BRIGHT "%s%s" NORMAL "\n"
        "And sorted according to: " BRIGHT "%s" NORMAL "\n"
        "Refresh rate is: " BRIGHT "%.2fs" NORMAL "\n"
        "\n"
        "  " BRIGHT "I" NORMAL "     Toggle usage of device id\n"
        "  " BRIGHT "V" NORMAL "     Toggle usage of VLAN id\n"
        "  " BRIGHT "s" NORMAL "     Toggle usage of src IP\n"
        "  " BRIGHT "d" NORMAL "     Toggle usage of dest IP\n"
        "  " BRIGHT "S" NORMAL "     Toggle usage of src port\n"
        "  " BRIGHT "D" NORMAL "     Toggle usage of dest port\n"
        "  " BRIGHT "m" NORMAL "     Toggle usage of src MAC\n"
        "  " BRIGHT "M" NORMAL "     Toggle usage of dest MAC\n"
        "  " BRIGHT "p" NORMAL "     Toggle usage of IP protocol\n"
        "  " BRIGHT "P" NORMAL "     Toggle usage of Ethernet protocol\n"
        "  " BRIGHT "v" NORMAL "     Toggle usage of IP version\n"
        "  " BRIGHT "n" NORMAL "     Toggle usage of protocol stack\n"
        "  " BRIGHT "N" NORMAL "     Display short protocol stack\n"
        "  " BRIGHT "k" NORMAL "     Toggle sort field (volume or packets)\n"
        "  " BRIGHT "b" NORMAL "     Bidirectional\n"
        "\n"
        "  " BRIGHT "+/-" NORMAL "   Refresh rate twice faster/slower\n"
        "  " BRIGHT "h,H,?" NORMAL " this help screen\n"
        "  " BRIGHT "q" NORMAL "     return to main screen\n"
        "  " BRIGHT "q,^C" NORMAL "  quit\n",
        current_key_2_str(),
        bidirectional ? " (bidirectional)":"",
        sort_by == VOLUME ? "Volume":"Packets",
        refresh_rate/1000000.);
}

// Key handling function
static void handle_key(char c)
{
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
        case 'N': shorten_proto_stack ^= 1; break;
        case 'b': bidirectional ^= 1; break;
        case 'k': sort_by = sort_by == VOLUME ? PACKETS:VOLUME; break;
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
    // Refresh help page after each keystroke
    mutex_lock(&cells_lock);
    if (display_help) do_display_help();
    else do_display_top(&last_display);
    mutex_unlock(&cells_lock);
}

/*
 * Callback
 */

static void pkt_callback(struct proto_subscriber unused_ *s, struct proto_info const *last, size_t unused_ cap_len, uint8_t const unused_ *packet, struct timeval const *now)
{
    mutex_lock(&cells_lock);

    if (! timeval_is_set(&start_counting)) start_counting = *now;

    if (! display_help) try_display(now);

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

    packets_count ++;
    bytes_count += cap->info.payload;
quit:
    mutex_unlock(&cells_lock);
}

static struct proto_subscriber subscription;

/*
 * Init
 */

void on_load(void)
{
    SLOG(LOG_INFO, "NetTop loaded");

    term_init(&handle_key);

    objalloc_init();
    hash_init();
    cli_register("NetTop plugin", nettop_opts, NB_ELEMS(nettop_opts));
    HASH_INIT(&nettop_cells, 30011, "nettop hitters");
    mutex_ctor(&cells_lock, "nettop lock");
    hook_subscriber_ctor(&pkt_hook, &subscription, pkt_callback);
}

void on_unload(void)
{
    SLOG(LOG_INFO, "NetTop unloading");

    term_fini();

    hook_subscriber_dtor(&pkt_hook, &subscription);
    HASH_DEINIT(&nettop_cells);
//    mutex_dtor(&cells_lock); nope since another thread may keep sending a few more packets
    cli_unregister(nettop_opts);
    hash_fini();
    objalloc_fini();
}
