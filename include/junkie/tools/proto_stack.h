// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef PROTO_STACK_H_130521
#define PROTO_STACK_H_130521
#include <stdint.h>
#include <junkie/proto/proto.h>

struct proto_stack {
    uint8_t depth;
    char name[128];
};

/// Replace the given proto_stack with the current one if it's bigger
int proto_stack_update(struct proto_stack *, struct proto_info const *);

#endif
