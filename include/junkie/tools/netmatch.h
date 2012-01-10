// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef NETMATCH_H_111229
#define NETMATCH_H_111229

#include <stdint.h>
#include <junkie/proto/proto.h>

struct npc_register {
    intptr_t value;
    size_t size;
};

typedef bool npc_match_fn(struct proto_info const *info, struct npc_register *regfile);

#endif
