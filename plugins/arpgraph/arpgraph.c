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
#include <stdlib.h>
#include <stdio.h>
#include "junkie/cpp.h"
#include "junkie/tools/cli.h"
#include "junkie/tools/objalloc.h"
#include "junkie/tools/tempstr.h"
#include "junkie/tools/hash.h"
#include "junkie/proto/arp.h"

// Global parameters settable from the command line
#define DEFAULT_MONITORING_PERIOD 120 // seconds
static unsigned opt_monitoring_period = DEFAULT_MONITORING_PERIOD;
static bool opt_loop = false;

// A Host is identified by it's IP address, and we store it's MAC as well.

struct host {
    struct ip_addr ip;
};

static void host_ctor(struct host *host, struct ip_addr const *ip)
{
    SLOG(LOG_DEBUG, "Construct host for %s", ip_addr_2_str(ip));
    host->ip = *ip;
}

static void host_dtor(struct host unused_ *host)
{
    SLOG(LOG_DEBUG, "Destruct host %s", ip_addr_2_str(&host->ip));
}

// The hash of edges from host to host. Both key and values are hosts (ie. addresses of the struct hosts).

struct edge {
    HASH_ENTRY(edge) entry;
    struct edge_key {
        struct host hosts[2];  // from, to
    } key;
};

static HASH_TABLE(edges, edge) edges;

static void edge_key_ctor(struct edge_key *key, struct ip_addr const *a_ip, struct ip_addr const *b_ip)
{
    memset(key, 0, sizeof(*key));    // as it's used as a hash key
    host_ctor(key->hosts+0, a_ip);
    host_ctor(key->hosts+1, b_ip);
}

static void edge_key_dtor(struct edge_key *key)
{
    host_dtor(key->hosts+0);
    host_dtor(key->hosts+1);
}

static char const *edge_key_2_str(struct edge_key const *key)
{
    return tempstr_printf("\"%s\" -> \"%s\"",
            ip_addr_2_str(&key->hosts[0].ip),
            ip_addr_2_str(&key->hosts[1].ip));
}

static void edge_ctor(struct edge *edge, struct edge_key const *key)
{
    SLOG(LOG_DEBUG, "Construct edge %s", edge_key_2_str(key));
    edge->key = *key;

    HASH_TRY_REHASH(&edges, key, entry);
    HASH_INSERT(&edges, edge, &edge->key, entry);
}

// Check the edge is not already there before inserting
static struct edge *edge_new(struct edge_key const *key)
{
    struct edge *edge;
    HASH_LOOKUP(edge, &edges, key, key, entry);
    if (edge) {
        SLOG(LOG_DEBUG, "Edge already exist");
        return NULL;
    }

    edge = objalloc(sizeof(*edge), "edges");
    if (! edge) return NULL;

    edge_ctor(edge, key);
    return edge;
}

static void edge_dtor(struct edge *edge)
{
    SLOG(LOG_DEBUG, "Destruct edge %s", edge_key_2_str(&edge->key));
    HASH_REMOVE(&edges, edge, entry);
    edge_key_dtor(&edge->key);
}

static void edge_del(struct edge *edge)
{
    edge_dtor(edge);
    objfree(edge);
}

// Extension of the command line:
static struct cli_opt arpgraph_opts[] = {
    {
        { "monitoring-period", NULL }, NEEDS_ARG,
        "Listen ARP messages for this amount of second before outputing the graph (default: "STRIZE(DEFAULT_MONITORING_PERIOD)"s)",
        CLI_SET_UINT, { .uint = &opt_monitoring_period }
    }, {
        { "loop", NULL }, NULL,
        "Loop once a graph is outputed instead of quiting",
        CLI_SET_BOOL, { .boolean = &opt_loop }
    }
};

static void output_graph(void)
{
    printf("digraph arp {\n");

    struct edge *edge;
    HASH_FOREACH(edge, &edges, entry) {
        printf("\t%s\n", edge_key_2_str(&edge->key));
    }

    printf("}\n");
}

static void reset_edges(void)
{
    struct edge *edge, *tmp;
    HASH_FOREACH_SAFE(edge, &edges, entry, tmp) {
        edge_del(edge);
    }
}

static void pkt_callback(struct proto_subscriber unused_ *s, struct proto_info const *info, size_t unused_ cap_len, uint8_t const unused_ *packet, struct timeval const *now)
{
    static time_t last_output = 0;
    if (! last_output) {
        last_output = now->tv_sec;
    } else if (now->tv_sec > last_output + (time_t)opt_monitoring_period) {
        output_graph();
        reset_edges();
        last_output = now->tv_sec;
    }

    ASSIGN_INFO_CHK(arp, info, );
    if (arp->opcode != ARP_REPLY) return;
    if (! arp->proto_addr_is_ip) return;

    struct edge_key key;
    edge_key_ctor(&key, &arp->sender, &arp->target);
    (void)edge_new(&key);
    edge_key_dtor(&key);
}

static struct proto_subscriber subscription;

void on_load(void)
{
    objalloc_init();
    hash_init();
    SLOG(LOG_INFO, "Loading arpgraph");
    cli_register("Arpgraph plugin", arpgraph_opts, NB_ELEMS(arpgraph_opts));
    HASH_INIT(&edges, 103, "arpgraph edges");
    pkt_subscriber_ctor(&subscription, pkt_callback);
}

void on_unload(void)
{
    SLOG(LOG_INFO, "Unloading arpgraph");
    pkt_subscriber_dtor(&subscription);
    cli_unregister(arpgraph_opts);
    HASH_DEINIT(&edges);
    hash_fini();
    objalloc_fini();
}

