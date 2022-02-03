// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef NETTRACK_H_120126
#define NETTRACK_H_120126
#include <stdbool.h>
#include <ltdl.h>
#include "junkie/tools/queue.h"
#include "junkie/tools/log.h"
#include "junkie/tools/timeval.h"
#include "junkie/tools/mutex.h"
#include "junkie/netmatch.h"

extern LOG_CATEGORY_DEC(nettrack);

struct nt_state {
    LIST_ENTRY(nt_state) same_parent;   // entry on children list
    TAILQ_ENTRY(nt_state) same_index;   // entry on vertex index
    TAILQ_ENTRY(nt_state) same_vertex;  // entry on age_list
    /* When a new state is spawned we keep a relationship with parent/children,
     * so that it's possible to terminate a whole family. */
    struct nt_state *parent;
    struct nt_vertex *vertex;
    unsigned h_value; // where I'm located on vertex->states[] (no modulo applied)
    LIST_HEAD(nt_states, nt_state) children;    // protected by vertex->mutex
    struct npc_register *regfile;
    struct timeval last_used;   // states on same_index are ordered according to this filed (more recently used at head)
    struct timeval last_enter;  // used to find out the age of a state. states are ordered on same_vertex list according to this field (more recently entered at head)
    /* As a similar mecanism, we'd like to know if a state already moved in a run
     * (so that we can avoid moving several times the same state in a single updating run).
     * TODO: Ultimately we'd like to allow this on a node by node basis.
     * Notice that reusing last_enter for this would not work when clock does not
     * increase between two updating run, which happen often since a single packet
     * (thus a single timestamp) can trigger several runs. */
    uint64_t last_moved_run;    // See also graph->run_id
};

struct nt_vertex {
    char *name;
    struct mutex mutex; // protects age_list & index & states children list
    LIST_ENTRY(nt_vertex) same_graph;
    LIST_HEAD(nt_edges, nt_edge) outgoing_edges;
    struct nt_edges incoming_edges;
    // User defined actions on entry and on timeout
    npc_match_fn *entry_fn, *timeout_fn;
    int64_t timeout;   // if >0, number of seconds to keep an inactive state in here
    unsigned index_size;   // the index size (>=1)
    unsigned num_states;
    TAILQ_HEAD(nt_states_tq, nt_state) age_list;    // states are ordered here according to their date of entry
    struct nt_states_tq index[];  // the states currently waiting in this node (BEWARE: variable size!)
};

struct nt_edge {
    LIST_ENTRY(nt_edge) same_graph;
    struct nt_graph *graph;
    struct nt_vertex *from , *to;
    LIST_ENTRY(nt_edge) same_from, same_to;
    LIST_ENTRY(nt_edge) same_hook;
    npc_match_fn *match_fn;
    npc_match_fn *from_index_fn, *to_index_fn;
    int64_t min_age;    // if != 0, cross the edge only if its age is greater than this
    // what to do when taken
    bool spawn;  // ie create a new child (otherwise bring the matching state right here)
    bool grab;   // stop looking for other possible transitions
    unsigned death_range;  // terminate all descendants of my Nth parent (if 0, kill all my descendants). if ~0, no kill at all.
    // for statistics
    uint64_t num_matches, num_tries;
};

struct nt_graph {
    char *name;
    LIST_HEAD(nt_vertices, nt_vertex) vertices;
    LIST_ENTRY(nt_graph) entry; // in the list of all started graphs
    bool started;
    struct nt_edges edges;
    unsigned num_registers;
    lt_dlhandle lib;
    unsigned default_index_size;    // index size if not specified in the vertex
    uint64_t run_id;                // to uniquely (hum) identifies the successive updating runs
    // for statistics
    uint64_t num_frames;
    // The hooks
    // We need to register a callback for every parsers, then try all nodes whose last proto matches the called one.
    struct nt_parser_hook {
        struct proto_subscriber subscriber;
        struct proto *on_proto; // we keep this for unregistering to subscription
        // list of edges which test ends with this proto
        struct nt_edges edges;
        bool registered;    // we only subscribe to this hook when used (and avoid registering twice)
        struct nt_graph *graph; // backlink to the graph
    } parser_hooks[PROTO_CODE_MAX+1];
#   define FULL_PARSE_EVENT PROTO_CODE_MAX
};

void nettrack_init(void);
void nettrack_fini(void);

#endif
