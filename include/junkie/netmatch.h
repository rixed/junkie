// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef NETMATCH_H_111229
#define NETMATCH_H_111229

#include <stdint.h>
#include <stdbool.h>
#include <junkie/proto/proto.h>

struct npc_register {
    uintptr_t value;
    ssize_t size;   // <0 if value is unbound, 0 if unboxed, malloced size otherwise (may be > to required size, may be < sizeof(intptr_t) (for strings for instance))
};

typedef uintptr_t npc_match_fn(struct proto_info const *info, struct npc_register const *prev_regfile, struct npc_register *new_regfile);

// The following structures are used by nettrack to describe the event graph

struct nt_vertex_def {
    char const *name;
    npc_match_fn *entry_fn;
    unsigned index_size;    // 0 for default
    int64_t timeout;
};

struct nt_edge_def {
    npc_match_fn *match_fn;
    enum proto_code inner_proto;
    char const *from_vertex, *to_vertex;
    npc_match_fn *from_index_fn, *to_index_fn;
    int64_t min_age;
    bool spawn;
    bool grab;
};

#endif
