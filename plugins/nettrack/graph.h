// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef GRAPH_H_120126
#define GRAPH_H_120126
#include <stdbool.h>
#include <ltdl.h>
#include "junkie/tools/queue.h"
#include "junkie/tools/netmatch.h"

// FIXME: some locks for all these lists

struct nt_state {
    LIST_ENTRY(nt_state) siblings, same_edge;
    /* When a new state is spawned we keep a relationship with parent/children,
     * so that it's possible to terminate a whole family. */
    struct nt_state *parent;
    LIST_HEAD(nt_states, nt_state) children;
    struct npc_register regfile[];  // Beware! Variable size!
};

struct nt_edge {
    char *name;
    LIST_ENTRY(nt_edge) same_graph;
    struct nt_states states; // the states currently waiting in this node
     LIST_HEAD(nt_vertices, nt_vertex) outgoing_vertices;
    struct nt_vertices incoming_vertices;
    // User defined actions
    // TODO timeout, etc
};

struct nt_vertex {
    LIST_ENTRY(nt_vertex) same_graph;
    struct nt_edge *from , *to;
    LIST_ENTRY(nt_vertex) same_from, same_to;
    npc_match_fn *match_fn;
    // what to do when taken
    bool spawn;  // ie create a new child (otherwise bring the matching state right here)
    bool grab;   // stop looking for other possible transitions
    unsigned death_range;  // terminate all descendants of my Nth parent (if 0, kill all my descendants). if ~0, no kill at all.
};

struct nt_graph {
    char *name;
    LIST_HEAD(nt_edges, nt_edge) edges;
    struct nt_vertices vertices;
    unsigned nb_registers;
    lt_dlhandle lib;
};

struct nt_state *nt_state_new(struct nt_state *parent, struct nt_graph *, struct nt_edge *);
void nt_state_del(struct nt_state *);
struct nt_edge *nt_edge_new(char const *name, struct nt_graph *);
void nt_edge_del(struct nt_edge *);
struct nt_vertex *nt_vertex_new(struct nt_graph *, struct nt_edge *from, struct nt_edge *to, char const *match_fn_name, bool spawn, bool grab, unsigned death_range);
void nt_vertex_del(struct nt_vertex *);
struct nt_graph *nt_graph_new(char const *name, char const *libname, unsigned nb_registers);
void nt_graph_del(struct nt_graph *);

void nt_graph_init(void);
void nt_graph_fini(void);

#endif
