// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab

#ifndef SDPER_H_100510
#define SDPER_H_100510

#include <stdint.h>
#include "proto/liner.h"

struct sdper {

    // For header fields
    unsigned num_fields;

    struct sdper_field {
        size_t length;
        char const *name;
        int (*cb)(unsigned field, struct liner *, void *);
    } const *fields;

};

int sdper_parse(struct sdper const *, size_t *head_sz, uint8_t const *packet, size_t packet_len, void *);

#endif
