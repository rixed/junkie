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
#include "junkie/proto/proto.h"
#include "junkie/cpp.h"
#include "junkie/tools/ext.h"
#include "junkie/tools/mallocer.h"
#include "nettrack.h"

LOG_CATEGORY_DEF(nettrack);
#undef LOG_CAT
#define LOG_CAT nettrack_log_category

static MALLOCER_DEF(nettrack);

/*
 * Register Files
 */

static struct npc_register *npc_regfile_new(unsigned nb_registers)
{
    size_t size = sizeof(struct npc_register) * nb_registers;
    struct npc_register *regfile = MALLOC(nettrack, size);
    if (! regfile) return NULL;

    memset(regfile, 0, size);
    return regfile;
}

static void npc_regfile_del(struct npc_register *regfile, unsigned nb_registers)
{
    for (unsigned r = 0; r < nb_registers; r++) {
        if (regfile[r].value && regfile[r].size>0) {
            free((void *)regfile[r].value); // beware that individual registers are mallocated with malloc not MALLOC
        }
    }
    FREE(regfile);
}

static struct npc_register *npc_regfile_copy(struct npc_register *regfile, unsigned nb_registers)
{
    struct npc_register *copy = npc_regfile_new(nb_registers);
    if (! copy) return NULL;

    for (unsigned r = 0; r < nb_registers; r++) {
        copy[r].size = regfile[r].size;
        if (regfile[r].value && regfile[r].size>0) {
            copy[r].value = (uintptr_t)malloc(copy[r].size);
            assert(copy[r].value);  // FIXME
            memcpy((void *)copy[r].value, (void *)regfile[r].value, copy[r].size);
        } else {
            copy[r].value = regfile[r].value;
        }
    }

    return copy;
}

/*
 * States
 */

static int nt_state_ctor(struct nt_state *state, struct nt_state *parent, struct nt_edge *edge, struct npc_register *regfile)
{
    SLOG(LOG_DEBUG, "Construct state@%p from state@%p, in edge %s", state, parent, edge->name);

    state->regfile = regfile;
    state->parent = parent;
    if (parent) LIST_INSERT_HEAD(&parent->children, state, siblings);
    LIST_INSERT_HEAD(&edge->states, state, same_edge);
    LIST_INIT(&state->children);

    return 0;
}

static struct nt_state *nt_state_new(struct nt_state *parent, struct nt_edge *edge, struct npc_register *regfile)
{
    struct nt_state *state = MALLOC(nettrack, sizeof(*state));
    if (! state) return NULL;
    if (0 != nt_state_ctor(state, parent, edge, regfile)) {
        FREE(state);
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
        LIST_REMOVE(state, siblings);
        state->parent = NULL;
    }
    LIST_REMOVE(state, same_edge);

    if (state->regfile) {
        npc_regfile_del(state->regfile, graph->nb_registers);
        state->regfile = NULL;
    }
}

static void nt_state_del(struct nt_state *state, struct nt_graph *graph)
{
    nt_state_dtor(state, graph);
    FREE(state);
}

static void nt_state_move(struct nt_state *state, struct nt_edge *edge)
{
    SLOG(LOG_DEBUG, "Moving state@%p to edge %s", state, edge->name);
    LIST_REMOVE(state, same_edge);
    LIST_INSERT_HEAD(&edge->states, state, same_edge);
}

/*
 * Edges
 */

static int nt_edge_ctor(struct nt_edge *edge, char const *name, struct nt_graph *graph)
{
    SLOG(LOG_DEBUG, "Construct new edge %s", name);

    edge->name = STRDUP(nettrack, name);
    LIST_INIT(&edge->outgoing_vertices);
    LIST_INIT(&edge->incoming_vertices);
    LIST_INIT(&edge->states);
    LIST_INSERT_HEAD(&graph->edges, edge, same_graph);

    // An edge named "root" starts with a nul state
    if (0 == strcmp("root", name)) {
        struct npc_register *regfile = npc_regfile_new(graph->nb_registers);
        if (! regfile) return -1;
        if (! nt_state_new(NULL, edge, regfile)) {
            npc_regfile_del(regfile, graph->nb_registers);
            return -1;
        }
    }

    return 0;
}

static struct nt_edge *nt_edge_new(char const *name, struct nt_graph *graph)
{
    struct nt_edge *edge = MALLOC(nettrack, sizeof(*edge));
    if (! edge) return NULL;
    if (0 != nt_edge_ctor(edge, name, graph)) {
        FREE(edge);
        return NULL;
    }
    return edge;
}

static void nt_vertex_del(struct nt_vertex *);
static void nt_edge_dtor(struct nt_edge *edge, struct nt_graph *graph)
{
    SLOG(LOG_DEBUG, "Destruct edge %s", edge->name);

    // Delete all our states
    struct nt_state *state;
    while (NULL != (state = LIST_FIRST(&edge->states))) {
        nt_state_del(state, graph);
    }

    // Then all the vertices using us
    struct nt_vertex *vertex;
    while (NULL != (vertex = LIST_FIRST(&edge->outgoing_vertices))) {
        nt_vertex_del(vertex);
    }
    while (NULL != (vertex = LIST_FIRST(&edge->incoming_vertices))) {
        nt_vertex_del(vertex);
    }

    LIST_REMOVE(edge, same_graph);

    FREE(edge->name);
    edge->name = NULL;
}

static void nt_edge_del(struct nt_edge *edge, struct nt_graph *graph)
{
    nt_edge_dtor(edge, graph);
    FREE(edge);
}


/*
 * Vertex
 */

static int nt_vertex_ctor(struct nt_vertex *vertex, struct nt_graph *graph, struct nt_edge *from, struct nt_edge *to, char const *match_fn_name, bool spawn, bool grab, unsigned death_range)
{
    SLOG(LOG_DEBUG, "Construct new vertex@%p", vertex);

    vertex->match_fn = lt_dlsym(graph->lib, match_fn_name);
    if (! vertex->match_fn) {
        SLOG(LOG_ERR, "Cannot find match function %s", match_fn_name);
        return -1;
    }
    vertex->from = from;
    vertex->to = to;
    vertex->spawn = spawn;
    vertex->grab = grab;
    vertex->death_range = death_range;
    vertex->nb_matches = vertex->nb_tries = 0;
    LIST_INSERT_HEAD(&from->outgoing_vertices, vertex, same_from);
    LIST_INSERT_HEAD(&to->incoming_vertices, vertex, same_to);
    LIST_INSERT_HEAD(&graph->vertices, vertex, same_graph);

    return 0;
}

static struct nt_vertex *nt_vertex_new(struct nt_graph *graph, struct nt_edge *from, struct nt_edge *to, char const *match_fn_name, bool spawn, bool grab, unsigned death_range)
{
    struct nt_vertex *vertex = MALLOC(nettrack, sizeof(*vertex));
    if (! vertex) return NULL;
    if (0 != nt_vertex_ctor(vertex, graph, from, to, match_fn_name, spawn, grab, death_range)) {
        FREE(vertex);
        return NULL;
    }
    return vertex;
}

static void nt_vertex_dtor(struct nt_vertex *vertex)
{
    SLOG(LOG_DEBUG, "Destruct vertex@%p", vertex);

    LIST_REMOVE(vertex, same_from);
    LIST_REMOVE(vertex, same_to);
    LIST_REMOVE(vertex, same_graph);

    vertex->match_fn = NULL;
}

static void nt_vertex_del(struct nt_vertex *vertex)
{
    nt_vertex_dtor(vertex);
    FREE(vertex);
}

/*
 * Graph
 */

static LIST_HEAD(nt_graphs, nt_graph) started_graphs;

static int nt_graph_ctor(struct nt_graph *graph, char const *name, char const *libname, unsigned nb_registers)
{
    SLOG(LOG_DEBUG, "Construct new graph %s", name);

    graph->nb_registers = nb_registers;
    graph->lib = lt_dlopen(libname);
    if (! graph->lib) {
        SLOG(LOG_ERR, "Cannot load netmatch shared object %s: %s", libname, lt_dlerror());
        return -1;
    }
    graph->name = STRDUP(nettrack, name);
    graph->started = false;
    graph->nb_frames = 0;

    LIST_INIT(&graph->edges);
    LIST_INIT(&graph->vertices);

    return 0;
}

static struct nt_graph *nt_graph_new(char const *name, char const *libname, unsigned nb_registers)
{
    struct nt_graph *graph = MALLOC(nettrack, sizeof(*graph));
    if (! graph) return NULL;
    if (0 != nt_graph_ctor(graph, name, libname, nb_registers)) {
        FREE(graph);
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

    // Delete all our edges
    struct nt_edge *edge;
    while (NULL != (edge = LIST_FIRST(&graph->edges))) {
        nt_edge_del(edge, graph);
    }
    // Then we are not supposed to have any vertex left
    assert(LIST_EMPTY(&graph->vertices));

    (void)lt_dlclose(graph->lib);
    graph->lib = NULL;

    FREE(graph->name);
    graph->name = NULL;
}

static void nt_graph_del(struct nt_graph *graph)
{
    nt_graph_dtor(graph);
    FREE(graph);
}

/*
 * Update graph with proto_infos
 */

static int nt_graph_update(struct nt_graph *graph, struct proto_info const *last, size_t cap_len, uint8_t const *packet)
{
    SLOG(LOG_DEBUG, "Updating graph %s", graph->name);
    (void)cap_len;
    (void)packet;

    graph->nb_frames ++;

    // Simple method: loop over all vertices, then over all states from the departure region
    struct nt_vertex *vertex;
    LIST_FOREACH(vertex, &graph->vertices, same_graph) {
        struct nt_state *state;
        LIST_FOREACH(state, &vertex->from->states, same_edge) {
            SLOG(LOG_DEBUG, "Testing state from edge %s for %s into %s",
                vertex->from->name,
                vertex->spawn ? "spawn":"move",
                vertex->to->name);
            vertex->nb_tries ++;
            // do the match with a copy of the regfile (FIXME: delayed bindings + prevent use of new bindings in same expression would be much faster)
            struct npc_register *tmp_regfile = npc_regfile_copy(state->regfile, graph->nb_registers);
            if (! tmp_regfile) return -1;
            if (vertex->match_fn(last, tmp_regfile)) {
                SLOG(LOG_DEBUG, "Match!");
                vertex->nb_matches ++;
                // TODO: actually spawn/move the state
                if (vertex->spawn) {
                    if (! nt_state_new(state, vertex->to, tmp_regfile)) {
                        npc_regfile_del(tmp_regfile, graph->nb_registers);
                    }
                } else {    // move the whole state
                    npc_regfile_del(state->regfile, graph->nb_registers);
                    state->regfile = tmp_regfile;
                    nt_state_move(state, vertex->to);
                }
                if (vertex->grab) goto quit;
            } else {
                SLOG(LOG_DEBUG, "No match");
                npc_regfile_del(tmp_regfile, graph->nb_registers);
            }
        }
    }
quit:

    return 0;
}

int nettrack_callbacks(struct proto_info const *last, size_t cap_len, uint8_t const *packet)
{
    struct nt_graph *graph;
    LIST_FOREACH(graph, &started_graphs, entry) {
        if (0 != nt_graph_update(graph, last, cap_len, packet)) return -1;
    }
    return 0;
}

/*
 * Extensions
 *
 * It's enough to have a single make-graph function, taking as parameters whatever is required to create the whole graph
 * (except that match expressions are replaced by name of the C function).
 * For instance, here is how a graph might be defined:
 *
 * (make-nettrack "sample graph" "/tmp/libfile.so" nb-registers
 *   ; list of edges
 *   '((root)
 *     (tcp-syn) ; merely the names. Later: timeout, etc...
 *     (etc...))
 *   ; list of vertices
 *   '((match-fun1 root tcp-syn spawn (kill 2))
 *     (match-fun2 root blabla ...)
 *     (etc...)))
 *
 * This returns a smob object that can later be started, deleted, queried for stats, ...
 * but not edited (cannot add/remove edges not vertices).
 */

static void add_edge(struct nt_graph *graph, SCM edge_)
{
    // for now, a edge is merely a list with a single symbol, the name
    SCM name_ = scm_car(edge_);
    struct nt_edge *edge = nt_edge_new(scm_to_tempstr(name_), graph);
    if (! edge) scm_throw(scm_from_latin1_symbol("cannot-create-nt-edge"), scm_list_1(name_));
}

// Will create the edge with default attributes if not found
static struct nt_edge *nt_edge_lookup(struct nt_graph *graph, char const *name)
{
    struct nt_edge *edge;
    LIST_FOREACH(edge, &graph->edges, same_graph) {
        if (0 == strcmp(name, edge->name)) return edge;
    }

    // Create a new one
    return nt_edge_new(name, graph);
}

static SCM spawn_sym;
static SCM grab_sym;
static SCM kill_sym;

static void add_vertex(struct nt_graph *graph, SCM vertex_)
{
    // vertex is a list of: match-name edge-name, edge-name, param
    // where param can be: spawn, grab, (kill n) ...
    SCM name_ = scm_car(vertex_);
    vertex_ = scm_cdr(vertex_);

    struct nt_edge *from = nt_edge_lookup(graph, scm_to_tempstr(scm_car(vertex_)));
    if (! from) scm_throw(scm_from_latin1_symbol("cannot-create-nt-edge"), scm_list_1(scm_car(vertex_)));
    vertex_ = scm_cdr(vertex_);

    struct nt_edge *to   = nt_edge_lookup(graph, scm_to_tempstr(scm_car(vertex_)));
    if (! to) scm_throw(scm_from_latin1_symbol("cannot-create-nt-edge"), scm_list_1(scm_car(vertex_)));
    vertex_ = scm_cdr(vertex_);

    bool spawn = false;
    bool grab = false;
    unsigned death_range = 0;

    while (! scm_is_null(vertex_)) {
        SCM param = scm_car(vertex_);
        if (scm_eq_p(param, spawn_sym)) {
            spawn = true;
        } else if (scm_eq_p(param, grab_sym)) {
            grab = true;
        } else if (scm_is_true(scm_list_p(param)) && scm_eq_p(scm_car(param), kill_sym)) {
            death_range = scm_to_uint(scm_cadr(param));
        } else {
            scm_throw(scm_from_latin1_symbol("unknown-vertex-parameter"), scm_list_1(param));
        }
        vertex_ = scm_cdr(vertex_);
    }

    struct nt_vertex *vertex = nt_vertex_new(graph, from, to, scm_to_tempstr(name_), spawn, grab, death_range);
    if (! vertex) scm_throw(scm_from_latin1_symbol("cannot-create-nt-vertex"), scm_list_1(name_));
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

    struct nt_edge *edge;
    LIST_FOREACH(edge, &graph->edges, same_graph) {
        char const *l = tempstr_printf("\n  edge %s%s%s", edge->name,
            LIST_EMPTY(&edge->outgoing_vertices)? " noOut":"",
            LIST_EMPTY(&edge->incoming_vertices)? " noIn":"");
        scm_puts(l, port);
    }

    struct nt_vertex *vertex;
    LIST_FOREACH(vertex, &graph->vertices, same_graph) {
        char const *l = tempstr_printf("\n  vertex %s -> %s", vertex->from->name, vertex->to->name);
        scm_puts(l, port);
    }

    scm_puts(" >", port);

    return 1;   // success
}

static struct ext_function sg_make_nettrack;
static SCM g_make_nettrack(SCM name_, SCM libname_, SCM nb_registers_, SCM edges_, SCM vertices_)
{
    scm_dynwind_begin(0);

    // Create an empty graph
    struct nt_graph *graph = nt_graph_new(scm_to_tempstr(name_), scm_to_tempstr(libname_), scm_to_uint(nb_registers_));
    if (! graph) {
        scm_throw(scm_from_latin1_symbol("cannot-create-nt-graph"), scm_list_1(name_));
        assert(!"Never reached");
    }
    scm_dynwind_unwind_handler((void (*)(void *))nt_graph_del, graph, 0);

    // Create edges
    while (! scm_is_null(edges_)) {
        add_edge(graph, scm_car(edges_));
        edges_ = scm_cdr(edges_);
    }

    // Create vertices
    while (! scm_is_null(vertices_)) {
        add_vertex(graph, scm_car(vertices_));
        vertices_ = scm_cdr(vertices_);
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
    mallocer_init();
    MALLOCER_INIT(nettrack);
    spawn_sym = scm_permanent_object(scm_from_latin1_symbol("spawn"));
    grab_sym  = scm_permanent_object(scm_from_latin1_symbol("grab"));
    kill_sym  = scm_permanent_object(scm_from_latin1_symbol("kill"));

    LIST_INIT(&started_graphs);

    // Create a SMOB for nt_graph
    graph_tag = scm_make_smob_type("nettrack-graph", sizeof(struct nt_graph));
    scm_set_smob_free(graph_tag, free_graph_smob);
    scm_set_smob_print(graph_tag, print_graph_smob);
    ext_function_ctor(&sg_make_nettrack,
        "make-nettrack", 5, 0, 0, g_make_nettrack,
        "(make-nettrack \"sample graph\" \"/tmp/libfile.so\" nb-registers\n"
        "  ; list of edges (optional)\n"
        "  '((root)\n"
        "    (tcp-syn) ; merely the names. Later: timeout, etc...\n"
        "    (etc...))\n"
        "  ; list of vertices\n"
        "  '((\"match-fun1\" root tcp-syn spawn (kill 2))\n"
        "    (\"match-fun2\" root blabla ...)\n"
        "    (etc...))) : create a nettrack graph.\n"
        "Note: you are not supposed to use this directly.\n");

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

    mallocer_fini();
	ext_fini();
    log_category_nettrack_fini();
}
