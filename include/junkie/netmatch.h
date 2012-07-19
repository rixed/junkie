// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef NETMATCH_H_111229
#define NETMATCH_H_111229

#include <ltdl.h>
#include <stdint.h>
#include <stdbool.h>
#include <junkie/proto/proto.h>

/*
 * Netmatch is a simple way to define C-compiled packet matching functions from guile
 */

struct npc_register {
    uintptr_t value;
    ssize_t size;   // <0 if value is unbound, 0 if unboxed, malloced size otherwise (may be > to required size, may be < sizeof(intptr_t) (for strings for instance))
};

typedef uintptr_t npc_match_fn(struct proto_info const *info, struct npc_register const rest, struct npc_register const *prev_regfile, struct npc_register *new_regfile);

// handy structure to stores a netmatch in C
struct netmatch_filter {
    char *libname;
    unsigned nb_registers;
    struct npc_register *regfile;
    lt_dlhandle handle;
    npc_match_fn *match_fun;
};

int netmatch_filter_ctor(struct netmatch_filter *netmatch, char const *libname, unsigned nb_regs);
void netmatch_filter_dtor(struct netmatch_filter *netmatch);

/*
 * NetTrack uses NetMatch to build a state machine to match consecutive events.
 */

struct nt_vertex_def {
    char const *name;
    npc_match_fn *entry_fn;
    unsigned index_size;    // 0 for default
    int64_t timeout;
};

struct nt_edge_def {
    npc_match_fn *match_fn;
    enum proto_code inner_proto;
    bool per_packet;    // Ideally, we'd like to choose any trigger by "name". But for now we have only two kinds of trigger: per packet and per proto.
    char const *from_vertex, *to_vertex;
    npc_match_fn *from_index_fn, *to_index_fn;
    int64_t min_age;
    bool spawn;
    bool grab;
};

#endif
