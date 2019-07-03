// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef HTTPER_H_100505
#define HTTPER_H_100505
#include <stdint.h>
#include "junkie/tools/radix_tree.h"
#include "proto/liner.h"

struct httper_string {
    char const *name;
    size_t len;
    int (*cb)(struct liner *, void *);    // returns -1 for parse error
};

struct httper {
    // For first command line
    struct radix_tree command_tree;
    // For header fields
    struct radix_tree field_tree;
};

void httper_ctor(struct httper *, size_t, struct httper_string const *, size_t, struct httper_string const *);
void httper_dtor(struct httper *);

/// @returns PROTO_PARSE_ERR if none of the given command was found
/// @returns PROTO_OK if a complete header was available
/// @returns PROTO_TOO_SHORT if the header was not complete
/// @note If you have several commands that share a common prefix you must order them longest first
enum proto_parse_status httper_parse(struct httper const *, size_t *head_sz, uint8_t const *packet, size_t packet_len, void *);

#endif
