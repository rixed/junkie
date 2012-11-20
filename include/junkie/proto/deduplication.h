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

#define DIGEST_SIZE MD4_DIGEST_LENGTH

struct digest_qcell;

struct digest_queue {
    struct ref ref;
    LIST_ENTRY(digest_queue) entry; // All existing digest_queues are chained together
#   define NB_QUEUES (MIN(CPU_MAX, 256))   /* Must not be greater that 256 since we use only one byte from digest to hash */
    struct digest_queue_ {
        struct mutex mutex; // protecting this queue
        // List of previously received packets, most recent first, ie loosely ordered according to frame timestamp
        TAILQ_HEAD(qcells, digest_qcell) qcells;
        unsigned length;    // size of qcells list
        // Deduplication variables (protected by the above mutex)
        bool comprehensive; // make a comprehensive search for dups (otherwise look only up to dt_max)
        struct timeval period_start;    // start of the deduplication period
        uint64_t dt_sum, dt_sum2;   // sum of all dups dt and dt^2 (in microseconds)
        unsigned dt_max;    // microseconds (only defined if period_start is set)
        unsigned nb_dups;   // dups found in this run
    } queues[NB_QUEUES];    // The queue is chosen according to digest hash, so that several distinct threads can perform lookups simultaneously.
    // Some stats for the user
    uint_least64_t nb_dup_found, nb_nodup_found;
    uint8_t dev_id;
};

/// Return a new ref on a digest_queue for given dev_id (will create a new one if needed)
struct digest_queue *digest_queue_get(uint8_t dev_id);

/// Unref a digest_queue (returns NULL)
void digest_queue_unref(struct digest_queue **);

bool digest_queue_find(struct digest_queue *dq, size_t cap_len, uint8_t *packet, struct timeval const *frame_tv);

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
