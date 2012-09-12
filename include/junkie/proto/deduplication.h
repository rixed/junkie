// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef DEDUPLICATION_H_110202
#define DEDUPLICATION_H_110202
#include <stdint.h>
#include <stdbool.h>
#include <junkie/proto/proto.h>
#include <junkie/tools/timeval.h>

bool digest_queue_find(size_t cap_len, uint8_t *packet, uint8_t dev_id, struct timeval const *frame_tv);

// FIXME: deduplication phase should be a proto on its own

struct dedup_proto_info {
    struct proto_info info;
    uint64_t dt;
};

/** Delay, in microseconds, after which a dup cannot be a dup any more but
 * must be considered a retransmission, and the other way around. */
unsigned max_dup_delay;

/// To be called each time a duplicate frame is found
int dup_subscriber_ctor(struct proto_subscriber *, proto_cb_t *);
void dup_subscriber_dtor(struct proto_subscriber *);

void digest_init(void);
void digest_fini(void);

#endif
