// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef DEDUPLICATION_H_110202
#define DEDUPLICATION_H_110202
#include <stdint.h>
#include <stdbool.h>
#include <junkie/proto/proto.h>
#include <junkie/tools/timeval.h>
#include <junkie/tools/queue.h>
#include <junkie/tools/ref.h>
#include <junkie/tools/hash.h>

#define DIGEST_SIZE MD4_DIGEST_LENGTH

struct digest_qcell;

struct digest_queue {
    struct ref ref;
    LIST_ENTRY(digest_queue) entry; // All existing digest_queues are chained together
#   define NB_QUEUES (MIN(CPU_MAX, 256))   /* Must not be greater that 256 since we use only one byte from digest to hash */
    struct digest_queue_ {
        struct mutex mutex; // protecting this queue
        // Previously received packets, indexed by their digests
        HASH_TABLE(qcells, digest_qcell) qcells;
    } queues[NB_QUEUES];    // The queue is chosen according to digest hash, so that several distinct threads can perform lookups simultaneously.
    // Some stats for the user
    uint_least64_t num_dup_found, num_nodup_found;
    uint8_t dev_id;
};

/// Return a new ref on a digest_queue for given dev_id (will create a new one if needed)
struct digest_queue *digest_queue_get(uint8_t dev_id);

/// Unref a digest_queue (returns NULL)
void digest_queue_unref(struct digest_queue **);

bool digest_queue_find(struct digest_queue *dq, size_t cap_len, uint8_t *packet, struct timeval const *frame_tv);

struct dedup_proto_info {
    struct proto_info info;
    uint64_t dt;    // delay between dup and original packet
};

/** Delay, in microseconds, after which a dup cannot be a dup any more but
 * must be considered a retransmission, and the other way around. */
unsigned max_dup_delay;

/// To be called each time a duplicate frame is found
struct hook dup_hook;

void digest_init(void);
void digest_fini(void);

#endif
