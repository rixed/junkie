// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef NETTRACK_H_120126
#define NETTRACK_H_120126
#include <stdbool.h>
#include <ltdl.h>
#include "junkie/tools/queue.h"
#include "junkie/tools/log.h"
#include "junkie/netmatch.h"

LOG_CATEGORY_DEC(nettrack);

// FIXME: some locks for all these lists

struct nt_state {
    LIST_ENTRY(nt_state) same_parent, same_vertex;
    /* When a new state is spawned we keep a relationship with parent/children,
     * so that it's possible to terminate a whole family. */
    struct nt_state *parent;
    LIST_HEAD(nt_states, nt_state) children;
    struct npc_register *regfile;
};

struct nt_vertex {
    char *name;
    LIST_ENTRY(nt_vertex) same_graph;
    struct nt_states states; // the states currently waiting in this node
    LIST_HEAD(nt_edges, nt_edge) outgoing_edges;
    struct nt_edges incoming_edges;
    // User defined actions
    npc_action_fn *action_fn;
    // TODO timeout, etc
};

struct nt_edge {
    LIST_ENTRY(nt_edge) same_graph;
    struct nt_graph *graph;
    struct nt_vertex *from , *to;
    LIST_ENTRY(nt_edge) same_from, same_to;
    LIST_ENTRY(nt_edge) same_hook;
    npc_match_fn *match_fn;
    // what to do when taken
    bool spawn;  // ie create a new child (otherwise bring the matching state right here)
    bool grab;   // stop looking for other possible transitions
    unsigned death_range;  // terminate all descendants of my Nth parent (if 0, kill all my descendants). if ~0, no kill at all.
    // for statistics
    uint64_t nb_matches, nb_tries;
};

struct nt_graph {
    char *name;
    LIST_HEAD(nt_vertices, nt_vertex) vertices;
    LIST_ENTRY(nt_graph) entry; // in the list of all started graphs
    bool started;
    struct nt_edges edges;
    unsigned nb_registers;
    lt_dlhandle lib;
    // for statistics
    uint64_t nb_frames;
};

void nettrack_init(void);
void nettrack_fini(void);

#endif
