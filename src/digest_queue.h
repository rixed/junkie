// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef DIGEST_QUEUE_H_110202
#define DIGEST_QUEUE_H_110202
#include <stdint.h>
#include "pkt_source.h"

#define DIGEST_SIZE 16

struct digest_queue {
    struct digest_qcell {
        uint8_t digest[DIGEST_SIZE];
        struct timeval tv;
    } *digests;
    uint32_t idx;
    size_t size;
};

struct digest_queue *digest_queue_new(unsigned size);
void digest_queue_del(struct digest_queue *);

void digest_queue_push(struct digest_queue *, uint8_t digest[DIGEST_SIZE], const struct frame *);
void digest_frame(uint8_t *buf, struct frame *);

#endif
