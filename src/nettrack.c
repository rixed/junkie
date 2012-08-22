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
/* Here we handle the evolution of states in a graph which vertices
 * are predicates over previous state + new proto info (ie. match functions).
 */
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <inttypes.h>
#include "junkie/proto/proto.h"
#include "junkie/cpp.h"
#include "junkie/tools/ext.h"
#include "junkie/tools/objalloc.h"
#include "junkie/tools/tempstr.h"
#include "nettrack.h"

LOG_CATEGORY_DEF(nettrack);
#undef LOG_CAT
#define LOG_CAT nettrack_log_category

/*
 * Register Files
 */

static void npc_regfile_ctor(struct npc_register *regfile, unsigned nb_registers)
{
    for (unsigned r = 0; r < nb_registers; r++) {
        regfile[r].value = 0;
        regfile[r].size = -1;
    }
}

static struct npc_register *npc_regfile_new(unsigned nb_registers)
{
    size_t size = sizeof(struct npc_register) * nb_registers;
    struct npc_register *regfile = objalloc(size, "nettrack regfiles");
    if (! regfile) return NULL;

    npc_regfile_ctor(regfile, nb_registers);
    return regfile;
}

static void npc_regfile_dtor(struct npc_register *regfile, unsigned nb_registers)
{
    for (unsigned r = 0; r < nb_registers; r++) {
        if (regfile[r].size > 0 && regfile[r].value) {
            free((void *)regfile[r].value); // beware that individual registers are malloced with malloc not objalloc
        }
    }
}

static void npc_regfile_del(struct npc_register *regfile, unsigned nb_registers)
{
    npc_regfile_dtor(regfile, nb_registers);
    objfree(regfile);
}

static void register_copy(struct npc_register *dst, struct npc_register const *src)
{
    dst->size = src->size;
    if (src->size > 0 && src->value) {
        dst->value = (uintptr_t)malloc(src->size);
        assert(dst->value);  // FIXME
        memcpy((void *)dst->value, (void *)src->value, src->size);
    } else {
        dst->value = src->value;
    }
}

/* Given the regular regfile prev_regfile and the new bindings of new_regfile, returns a fresh register with new bindings applied.
 * If steal_from_prev then the previous values may be moved from prev_regfile to the new one. In any cases the new values are. */
static struct npc_register *npc_regfile_merge(struct npc_register *prev_regfile, struct npc_register *new_regfile, unsigned nb_registers, bool steal_from_prev)
{
    struct npc_register *merged = npc_regfile_new(nb_registers);
    if (! merged) return NULL;

    for (unsigned r = 0; r < nb_registers; r++) {
        if (new_regfile[r].size < 0) {  // still unbound
            if (steal_from_prev) {
                merged[r] = prev_regfile[r];
                prev_regfile[r].size = -1;
            } else {
                register_copy(merged+r, prev_regfile+r);
            }
        } else {
            merged[r] = new_regfile[r];
            new_regfile[r].size = -1;
        }
    }

    return merged;
}

/*
 * States
 */

static int nt_state_ctor(struct nt_state *state, struct nt_state *parent, struct nt_vertex *vertex, struct npc_register *regfile, struct timeval const *now, unsigned index_h)
{
    SLOG(LOG_DEBUG, "Construct state@%p from state@%p, in vertex %s", state, parent, vertex->name);
    unsigned const index = index_h % vertex->index_size;

    state->regfile = regfile;
    state->parent = parent;
    state->vertex = vertex;
    state->index_h = index_h;
    if (parent) LIST_INSERT_HEAD(&parent->children, state, same_parent);
    TAILQ_INSERT_HEAD(&vertex->states[index], state, same_vertex);
    LIST_INIT(&state->children);
    state->last_used = state->last_enter = *now;
#   ifdef __GNUC__
    __sync_fetch_and_add(&vertex->nb_states, 1);
#   else
    vertex->nb_states ++;
#   endif

    return 0;
}

static struct nt_state *nt_state_new(struct nt_state *parent, struct nt_vertex *vertex, struct npc_register *regfile, struct timeval const *now, unsigned index_h)
{
    struct nt_state *state = objalloc(sizeof(*state), "nettrack states");
    if (! state) return NULL;
    if (0 != nt_state_ctor(state, parent, vertex, regfile, now, index_h)) {
        objfree(state);
        return NULL;
    }
    return state;
}

static void nt_state_del(struct nt_state *, struct nt_graph *);
static void nt_state_dtor(struct nt_state *state, struct nt_graph *graph)
{
    SLOG(LOG_DEBUG, "Destruct state@%p", state);

    // start by killing our children so that they can make use of us
    struct nt_state *child;
    while (NULL != (child = LIST_FIRST(&state->children))) {
        nt_state_del(child, graph);
    }

    if (state->parent) {
        LIST_REMOVE(state, same_parent);
        state->parent = NULL;
    }
    TAILQ_REMOVE(&state->vertex->states[state->index_h], state, same_vertex);
#   ifdef __GNUC__
    __sync_fetch_and_sub(&state->vertex->nb_states, 1);
#   else
    state->vertex.nb_states --;
#   endif

    if (state->regfile) {
        npc_regfile_del(state->regfile, graph->nb_registers);
        state->regfile = NULL;
    }
}

static void nt_state_del(struct nt_state *state, struct nt_graph *graph)
{
    nt_state_dtor(state, graph);
    objfree(state);
}

static void nt_state_move(struct nt_state *state, struct nt_vertex *to, unsigned index_h, struct timeval const *now)
{
    state->last_used = *now;

    if (state->vertex == to) return;

    state->last_enter = *now;

    SLOG(LOG_DEBUG, "Moving state@%p to vertex %s", state, to->name);

#   ifdef __GNUC__
    __sync_fetch_and_sub(&state->vertex->nb_states, 1);
    __sync_fetch_and_add(&to->nb_states, 1);
#   else
    state->vertex->nb_states --;
    to->nb_states ++;
#   endif

    unsigned const index = index_h % to->index_size;

    TAILQ_REMOVE(&state->vertex->states[state->index_h], state, same_vertex);
    TAILQ_INSERT_HEAD(&to->states[index], state, same_vertex);
    state->vertex = to;
    state->index_h = index;
}

/*
 * Vertices
 */

static int nt_vertex_ctor(struct nt_vertex *vertex, char const *name, struct nt_graph *graph, npc_match_fn *entry_fn, unsigned index_size, int64_t timeout)
{
    SLOG(LOG_DEBUG, "Construct new vertex %s with %u buckets (timeout=%"PRId64"us)", name, index_size, timeout);

    vertex->name = objalloc_strdup(name);
    vertex->index_size = index_size;
    assert(vertex->index_size >= 1);
    LIST_INIT(&vertex->outgoing_edges);
    LIST_INIT(&vertex->incoming_edges);
    LIST_INSERT_HEAD(&graph->vertices, vertex, same_graph);
    for (unsigned i = 0; i < vertex->index_size; i++) {
        TAILQ_INIT(&vertex->states[i]);
    }
    vertex->nb_states = 0;

    // A vertex named "root" starts with an initial state (and is not timeouted)
    if (0 == strcmp("root", name)) {
        struct timeval now;
        timeval_set_now(&now);
        for (unsigned i = 0; i < vertex->index_size; i++) { // actually, one state per index
            struct npc_register *regfile = npc_regfile_new(graph->nb_registers);
            if (! regfile) return -1;
            if (! nt_state_new(NULL, vertex, regfile, &now, 0)) {
                npc_regfile_del(regfile, graph->nb_registers);
                return -1;
            }
        }
        vertex->timeout = 0;
    } else {
        vertex->timeout = timeout;
    }

    // Additionally, there may be an entry function to be called whenever this vertex is entered.
    vertex->entry_fn = entry_fn;

    return 0;
}

static struct nt_vertex *nt_vertex_new(char const *name, struct nt_graph *graph, npc_match_fn *entry_fn, unsigned index_size, int64_t timeout)
{
    if (! index_size) index_size = graph->default_index_size;
    struct nt_vertex *vertex = objalloc(sizeof(*vertex) + index_size*sizeof(vertex->states[0]), "nettrack vertices");
    if (! vertex) return NULL;
    if (0 != nt_vertex_ctor(vertex, name, graph, entry_fn, index_size, timeout)) {
        objfree(vertex);
        return NULL;
    }
    return vertex;
}

static void nt_edge_del(struct nt_edge *);
static void nt_vertex_dtor(struct nt_vertex *vertex, struct nt_graph *graph)
{
    SLOG(LOG_DEBUG, "Destruct vertex %s", vertex->name);

    // Delete all our states
    for (unsigned i = 0; i < vertex->index_size; i++) {
        struct nt_state *state;
        while (NULL != (state = TAILQ_FIRST(&vertex->states[i]))) {
            nt_state_del(state, graph);
        }
    }

    // Then all the edges using us
    struct nt_edge *edge;
    while (NULL != (edge = LIST_FIRST(&vertex->outgoing_edges))) {
        nt_edge_del(edge);
    }
    while (NULL != (edge = LIST_FIRST(&vertex->incoming_edges))) {
        nt_edge_del(edge);
    }

    LIST_REMOVE(vertex, same_graph);

    objfree(vertex->name);
    vertex->name = NULL;
}

static void nt_vertex_del(struct nt_vertex *vertex, struct nt_graph *graph)
{
    nt_vertex_dtor(vertex, graph);
    objfree(vertex);
}


/*
 * Edges
 */

static proto_cb_t parser_hook;
static int nt_edge_ctor(struct nt_edge *edge, struct nt_graph *graph, struct nt_vertex *from, struct nt_vertex *to, npc_match_fn *match_fn, npc_match_fn *from_index_fn, npc_match_fn *to_index_fn, int64_t min_age, bool spawn, bool grab, struct proto *inner_proto, bool per_packet)
{
    SLOG(LOG_DEBUG, "Construct new edge@%p from %s to %s on proto %s", edge, from->name, to->name, inner_proto->name);

    edge->match_fn = match_fn;
    edge->from_index_fn = from_index_fn;
    edge->to_index_fn = to_index_fn;
    edge->from = from;
    edge->to = to;
    edge->min_age = min_age;
    edge->spawn = spawn;
    edge->grab = grab;
    edge->nb_matches = edge->nb_tries = 0;
    edge->graph = graph;
    LIST_INSERT_HEAD(&from->outgoing_edges, edge, same_from);
    LIST_INSERT_HEAD(&to->incoming_edges, edge, same_to);
    LIST_INSERT_HEAD(&graph->edges, edge, same_graph);
    unsigned const hook = per_packet ? FULL_PARSE_EVENT : inner_proto->code;
    LIST_INSERT_HEAD(&graph->parser_hooks[hook].edges, edge, same_hook);
    if (! graph->parser_hooks[hook].registered) {
        if (0 == (
            per_packet ?
                pkt_subscriber_ctor(&graph->parser_hooks[hook].subscriber, parser_hook) :
                proto_subscriber_ctor(&graph->parser_hooks[hook].subscriber, inner_proto, parser_hook))
        ) {
            graph->parser_hooks[hook].registered = true;
        }
    }

    return 0;
}

static struct nt_edge *nt_edge_new(struct nt_graph *graph, struct nt_vertex *from, struct nt_vertex *to, npc_match_fn *match_fn, npc_match_fn *from_index_fn, npc_match_fn *to_index_fn, int64_t min_age, bool spawn, bool grab, struct proto *inner_proto, bool per_packet)
{
    struct nt_edge *edge = objalloc(sizeof(*edge), "nettrack edges");
    if (! edge) return NULL;
    if (0 != nt_edge_ctor(edge, graph, from, to, match_fn, from_index_fn, to_index_fn, min_age, spawn, grab, inner_proto, per_packet)) {
        objfree(edge);
        return NULL;
    }
    return edge;
}

static void nt_edge_dtor(struct nt_edge *edge)
{
    SLOG(LOG_DEBUG, "Destruct edge@%p", edge);

    LIST_REMOVE(edge, same_from);
    LIST_REMOVE(edge, same_to);
    LIST_REMOVE(edge, same_graph);
    LIST_REMOVE(edge, same_hook);

    edge->graph = NULL;
    edge->match_fn = NULL;
}

static void nt_edge_del(struct nt_edge *edge)
{
    nt_edge_dtor(edge);
    objfree(edge);
}

/*
 * Graph
 */

static LIST_HEAD(nt_graphs, nt_graph) started_graphs;

static int nt_graph_ctor(struct nt_graph *graph, char const *name, char const *libname)
{
    SLOG(LOG_DEBUG, "Construct new graph %s", name);

    // Init parser_hooks
    for (unsigned h = 0; h < NB_ELEMS(graph->parser_hooks); h++) {
        graph->parser_hooks[h].registered = false;
        graph->parser_hooks[h].graph = graph;
        LIST_INIT(&graph->parser_hooks[h].edges);
    }

    graph->lib = lt_dlopen(libname);
    if (! graph->lib) {
        SLOG(LOG_ERR, "Cannot load netmatch shared object %s: %s", libname, lt_dlerror());
        return -1;
    }
    unsigned *uptr;
    if (NULL != (uptr = lt_dlsym(graph->lib, "nb_registers"))) {
        graph->nb_registers = *uptr;
    } else {
        SLOG(LOG_ERR, "Cannot find nb_registers in shared object %s", libname);
        (void)lt_dlclose(graph->lib);
        graph->lib = NULL;
        return -1;
    }
    if (NULL != (uptr = lt_dlsym(graph->lib, "default_index_size"))) {
        graph->default_index_size = *uptr;
    } else {
        SLOG(LOG_ERR, "Cannot find default_index_size in shared object %s", libname);
        (void)lt_dlclose(graph->lib);
        graph->lib = NULL;
        return -1;
    }

    graph->name = objalloc_strdup(name);
    graph->started = false;
    graph->nb_frames = 0;

    LIST_INIT(&graph->vertices);
    LIST_INIT(&graph->edges);

    return 0;
}

static struct nt_graph *nt_graph_new(char const *name, char const *libname)
{
    struct nt_graph *graph = objalloc(sizeof(*graph), "nettrack graphs");
    if (! graph) return NULL;
    if (0 != nt_graph_ctor(graph, name, libname)) {
        objfree(graph);
        return NULL;
    }
    return graph;
}

static void nt_graph_start(struct nt_graph *graph)
{
    if (graph->started) return;
    SLOG(LOG_DEBUG, "Starting nettracking with graph %s", graph->name);
    graph->started = true;
    LIST_INSERT_HEAD(&started_graphs, graph, entry);
}

static void nt_graph_stop(struct nt_graph *graph)
{
    if (! graph->started) return;
    SLOG(LOG_DEBUG, "Stopping nettracking with graph %s", graph->name);
    graph->started = false;
    LIST_REMOVE(graph, entry);
}

static void nt_graph_dtor(struct nt_graph *graph)
{
    SLOG(LOG_DEBUG, "Destruct graph %s", graph->name);

    nt_graph_stop(graph);

    // Delete all our vertices
    struct nt_vertex *vertex;
    while (NULL != (vertex = LIST_FIRST(&graph->vertices))) {
        nt_vertex_del(vertex, graph);
    }
    // Then we are not supposed to have any edge left
    assert(LIST_EMPTY(&graph->edges));

    (void)lt_dlclose(graph->lib);
    graph->lib = NULL;

    objfree(graph->name);
    graph->name = NULL;
}

static void nt_graph_del(struct nt_graph *graph)
{
    nt_graph_dtor(graph);
    objfree(graph);
}

/*
 * Update graph with proto_infos
 */

static void parser_hook(struct proto_subscriber *subscriber, struct proto_info const *last, size_t cap_len, uint8_t const *packet, struct timeval const *now)
{
    struct npc_register rest = { .size = cap_len, .value = (uintptr_t)packet };

    // Find the parser_hook
    struct nt_parser_hook *hook = DOWNCAST(subscriber, subscriber, nt_parser_hook);
    assert(hook >= hook->graph->parser_hooks+0);
    assert(hook < hook->graph->parser_hooks+(NB_ELEMS(hook->graph->parser_hooks)));
    assert(hook->registered);

    if (! hook->graph->started) return;

    SLOG(LOG_DEBUG, "Updating graph %s with inner info from %s", hook->graph->name, last->parser->proto->name);

    struct nt_edge *edge;
    LIST_FOREACH(edge, &hook->edges, same_hook) {
        // Test this edge for transition
        struct nt_state *state, *tmp;

        unsigned index_start = 0, index_stop = edge->from->index_size;  // by default, prepare to look into all hash buckets
        if (index_stop > 1 && edge->from_index_fn) {
            // Notice that the hash function for incomming packet is *not* allowed to use the regfile nor to bind anything
            index_start = edge->from_index_fn(last, rest, NULL, NULL) % edge->from->index_size;
            index_stop = index_start + 1;
            SLOG(LOG_DEBUG, "Using index at location %u", index_start);
        }
        for (unsigned index = index_start; index < index_stop; index++) {
            unsigned nb_collisions = 0;
            TAILQ_FOREACH_REVERSE_SAFE(state, &edge->from->states[index], nt_states_tq, same_vertex, tmp) {   // Beware that this state may move
                if (edge->from->timeout > 0LL && edge->from->timeout < timeval_sub(now, &state->last_used)) {
                    SLOG(LOG_DEBUG, "Timeouting state in vertex %s", edge->from->name);
                    nt_state_del(state, edge->graph);
                    continue;
                }
                if (!edge->match_fn && edge->min_age != 0 && timeval_sub(now, &state->last_enter) < edge->min_age) {
                    // if we are looking only for old states then exit early as soon as we met one that's young
                    break;
                }

                if (edge->match_fn && ++nb_collisions > 16) TIMED_SLOG(LOG_NOTICE, "%u collisions searching in %s, size=%u, index=%u/%u", nb_collisions, edge->from->name, edge->from->nb_states, index_stop-index_start, edge->from->index_size);
                SLOG(LOG_DEBUG, "Testing state@%p from vertex %s for %s into %s",
                        state,
                        edge->from->name,
                        edge->spawn ? "spawn":"move",
                        edge->to->name);
                edge->nb_tries ++;
                /* Delayed bindings:
                 *   Matching functions do not change the bindings of the regfile while performing the tests because
                 *   we want the binding to take effect only if the tests succeed. Also, since the test order is not
                 *   specified then a given test can not both bind and reference the same register. Thus we pass it
                 *   two regfiles: one with the actual bindings (read only) and an empty one for the new bindings. On
                 *   exit, if the test succeeded, the new bindings overwrite the previous ones; otherwise they are
                 *   discarded.
                 *   We try to do this as efficiently as possible by reusing the previously boxed values whenever
                 *   possible rather than reallocing/copying them.
                 * TODO:
                 *   - a flag per node telling if the match function write into the regfile or not would comes handy;
                 *   - prevent the test expressions to read and write the same register;
                 */
                struct npc_register tmp_regfile[edge->graph->nb_registers];
                npc_regfile_ctor(tmp_regfile, edge->graph->nb_registers);

                if (
                    (edge->min_age == 0 || timeval_sub(now, &state->last_enter) >= edge->min_age) &&
                    (edge->match_fn == NULL || edge->match_fn(last, rest, state->regfile, tmp_regfile))
                ) {
                    SLOG(LOG_DEBUG, "Match!");
                    edge->nb_matches ++;
                    // We need the merged state in all cases but when we have no action and don't keep the result
                    struct npc_register *merged_regfile = NULL;
                    if (edge->to->entry_fn || !LIST_EMPTY(&edge->to->outgoing_edges)) {
                        merged_regfile = npc_regfile_merge(state->regfile, tmp_regfile, edge->graph->nb_registers, !edge->spawn);
                        if (! merged_regfile) {
                            SLOG(LOG_WARNING, "Cannot create the new register file");
                            // so be it
                        }
                    }
                    // Call the entry function
                    if (edge->to->entry_fn && merged_regfile) {
                        SLOG(LOG_DEBUG, "Calling entry function for vertex '%s'", edge->to->name);
                        edge->to->entry_fn(last, rest, merged_regfile, NULL); // entry function is not supposed to bind anything... for now (FIXME).
                    }
                    // Now move/spawn/dispose of the state
                    // first we need to know the location in the index
                    unsigned index_h = 0;
                    if (edge->to->index_size > 1) { // we'd better have a hashing function then!
                        if (!edge->to_index_fn) {
                            SLOG(LOG_WARNING, "Don't know how to store spawned state in vertex %s, missing hashing function when coming from %s", edge->to->name, edge->from->name);
                            if (merged_regfile) npc_regfile_del(merged_regfile, edge->graph->nb_registers);
                            goto hell;
                        }
                        // Notice this hashing function can use the regfile but can still perform no bindings
                        index_h = edge->to_index_fn(last, rest, merged_regfile, NULL) % edge->to->index_size;
                        SLOG(LOG_DEBUG, "Will store at index location %u", index_h);
                    }
                    if (edge->spawn) {
                        if (!LIST_EMPTY(&edge->to->outgoing_edges) && merged_regfile) { // or we do not need to spawn anything
                            if (NULL == (state = nt_state_new(state, edge->to, merged_regfile, now, index_h))) {
                                npc_regfile_del(merged_regfile, edge->graph->nb_registers);
                            }
                        }
                    } else {    // move the whole state
                        if (LIST_EMPTY(&edge->to->outgoing_edges)) {  // rather dispose of former state
                            nt_state_del(state, edge->graph);
                        } else if (merged_regfile) {    // replace former regfile with new one
                            npc_regfile_del(state->regfile, edge->graph->nb_registers);
                            state->regfile = merged_regfile;
                            nt_state_move(state, edge->to, index_h, now);
                        }
                    }
hell:
                    npc_regfile_dtor(tmp_regfile, edge->graph->nb_registers);
                    if (edge->grab) return;
                } else {
                    SLOG(LOG_DEBUG, "No match");
                    npc_regfile_dtor(tmp_regfile, edge->graph->nb_registers);
                }
            }
        }
    }
}

/*
 * Extensions
 */

// Will create the vertex with default attributes if not found
static struct nt_vertex *nt_vertex_lookup(struct nt_graph *graph, char const *name)
{
    struct nt_vertex *vertex;
    LIST_FOREACH(vertex, &graph->vertices, same_graph) {
        if (0 == strcmp(name, vertex->name)) return vertex;
    }

    // Create a new one
    return nt_vertex_new(name, graph, NULL, 1, 1000000LL);
}

static scm_t_bits graph_tag;

static size_t free_graph_smob(SCM graph_smob)
{
    struct nt_graph *graph = (struct nt_graph *)SCM_SMOB_DATA(graph_smob);
    nt_graph_del(graph);
    return 0;
}

static int print_graph_smob(SCM graph_smob, SCM port, scm_print_state unused_ *pstate)
{
    struct nt_graph *graph = (struct nt_graph *)SCM_SMOB_DATA(graph_smob);

    char const *head = tempstr_printf("#<nettrack-graph %s with %u regs", graph->name, graph->nb_registers);
    scm_puts(head, port);

    struct nt_vertex *vertex;
    LIST_FOREACH(vertex, &graph->vertices, same_graph) {
        char const *l = tempstr_printf("\n  vertex %s%s%s", vertex->name,
            LIST_EMPTY(&vertex->outgoing_edges)? " noOut":"",
            LIST_EMPTY(&vertex->incoming_edges)? " noIn":"");
        scm_puts(l, port);
    }

    struct nt_edge *edge;
    LIST_FOREACH(edge, &graph->edges, same_graph) {
        char const *l = tempstr_printf("\n  edge %s -> %s", edge->from->name, edge->to->name);
        scm_puts(l, port);
    }

    scm_puts(" >", port);

    return 1;   // success
}

static struct ext_function sg_make_nettrack;
static SCM g_make_nettrack(SCM name_, SCM libname_)
{
    scm_dynwind_begin(0);

    // Create an empty graph
    struct nt_graph *graph = nt_graph_new(scm_to_tempstr(name_), scm_to_tempstr(libname_));
    if (! graph) {
        scm_throw(scm_from_latin1_symbol("cannot-create-nt-graph"), scm_list_1(name_));
        assert(!"Never reached");
    }
    scm_dynwind_unwind_handler((void (*)(void *))nt_graph_del, graph, 0);

    // Create vertices from declarations (others will be created hereafter with default settings)
    unsigned *nb_vertice_defs = lt_dlsym(graph->lib, "nb_vertice_defs");
    if (! nb_vertice_defs) {
        scm_throw(scm_from_latin1_symbol("cannot-create-nt-vertex"), scm_list_1(scm_from_latin1_string("nb_vertice_defs")));
        assert(!"Never reached");
    }
    struct nt_vertex_def *v_def = lt_dlsym(graph->lib, "vertice_defs");
    if (! v_def) {
        scm_throw(scm_from_latin1_symbol("cannot-create-nt-vertex"), scm_list_1(scm_from_latin1_string("vertice_defs")));
        assert(!"Never reached");
    }
    for (unsigned vi = 0; vi < *nb_vertice_defs; vi++) {
        struct nt_vertex *vertex = nt_vertex_new(v_def[vi].name, graph, v_def[vi].entry_fn, v_def[vi].index_size, v_def[vi].timeout);
        if (! vertex) {
            scm_throw(scm_from_latin1_symbol("cannot-create-nt-vertex"), scm_list_1(scm_from_locale_string(v_def[vi].name)));
            assert(!"Never reached");
        }
    }

    // Create edges (and other vertices)
    unsigned *nb_edge_defs = lt_dlsym(graph->lib, "nb_edge_defs");
    if (! nb_edge_defs) {
        scm_throw(scm_from_latin1_symbol("cannot-create-nt-vertex"), scm_list_1(scm_from_latin1_string("nb_edge_defs")));
        assert(!"Never reached");
    }
    struct nt_edge_def *e_def = lt_dlsym(graph->lib, "edge_defs");
    if (! e_def) {
        scm_throw(scm_from_latin1_symbol("cannot-create-nt-vertex"), scm_list_1(scm_from_latin1_string("edge_defs")));
        assert(!"Never reached");
    }
    for (unsigned e = 0; e < *nb_edge_defs; e++) {
        struct nt_vertex *from = nt_vertex_lookup(graph, e_def[e].from_vertex);
        if (! from) scm_throw(scm_from_latin1_symbol("cannot-create-nt-edge"), scm_list_1(scm_from_locale_string(e_def[e].from_vertex)));
        struct nt_vertex *to   = nt_vertex_lookup(graph, e_def[e].to_vertex);
        if (! to) scm_throw(scm_from_latin1_symbol("cannot-create-nt-edge"), scm_list_1(scm_from_locale_string(e_def[e].to_vertex)));
        struct proto *inner_proto = proto_of_code(e_def[e].inner_proto);
        if (! inner_proto) scm_throw(scm_from_latin1_symbol("cannot-create-nt-edge"), scm_list_2(scm_from_latin1_string("no such proto"), scm_from_uint(e_def[e].inner_proto)));
        struct nt_edge *edge = nt_edge_new(graph, from, to, e_def[e].match_fn, e_def[e].from_index_fn, e_def[e].to_index_fn, e_def[e].min_age, e_def[e].spawn, e_def[e].grab, inner_proto, e_def[e].per_packet);
        if (! edge) scm_throw(scm_from_latin1_symbol("cannot-create-nt-edge"), scm_list_2(scm_from_locale_string(e_def[e].from_vertex), scm_from_locale_string(e_def[e].to_vertex)));
    }

    // build the smob
    SCM smob;
    SCM_NEWSMOB(smob, graph_tag, graph);

    scm_dynwind_end();
    return smob;
}

static struct ext_function sg_nettrack_start;
static SCM g_nettrack_start(SCM graph_smob)
{
    scm_assert_smob_type(graph_tag, graph_smob);
    struct nt_graph *graph = (struct nt_graph *)SCM_SMOB_DATA(graph_smob);
    nt_graph_start(graph);
    return SCM_UNSPECIFIED;
}

static struct ext_function sg_nettrack_stop;
static SCM g_nettrack_stop(SCM graph_smob)
{
    scm_assert_smob_type(graph_tag, graph_smob);
    struct nt_graph *graph = (struct nt_graph *)SCM_SMOB_DATA(graph_smob);
    nt_graph_stop(graph);
    return SCM_UNSPECIFIED;
}

/*
 * Init
 */

static unsigned inited;
void nettrack_init(void)
{
    if (inited++) return;
    log_category_nettrack_init();
    ext_init();
    objalloc_init();

    LIST_INIT(&started_graphs);

    // Create a SMOB for nt_graph
    graph_tag = scm_make_smob_type("nettrack-graph", sizeof(struct nt_graph));
    scm_set_smob_free(graph_tag, free_graph_smob);
    scm_set_smob_print(graph_tag, print_graph_smob);
    ext_function_ctor(&sg_make_nettrack,
        // FIXME: should be load-nettrack, and all params but the libfile should be compiled herein.
        "make-nettrack", 2, 0, 0, g_make_nettrack,
        "(make-nettrack \"sample graph\" \"/tmp/libfile.so\"): create a nettrack graph.\n");

    ext_function_ctor(&sg_nettrack_start,
        "nettrack-start", 1, 0, 0, g_nettrack_start,
        "(nettrack-start graph): start listening events for this graph.\n"
        "See also (? 'nettrack-stop)\n");

    ext_function_ctor(&sg_nettrack_stop,
        "nettrack-stop", 1, 0, 0, g_nettrack_stop,
        "(nettrack-stop graph): stop listening events for this graph.\n"
        "See also (? 'nettrack-start)\n");
}

void nettrack_fini(void)
{
    if (--inited) return;

    objalloc_fini();
    ext_fini();
    log_category_nettrack_fini();
}
