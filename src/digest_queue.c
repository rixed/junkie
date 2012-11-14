// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2010, SecurActive.
 *
 * This file is part of Junkie.
 *
 * Junkie is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Junkie is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Junkie.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>
#include <sys/time.h>
#include <assert.h>
#include <math.h>
#include <openssl/md4.h>
#include "junkie/config.h"
#include "junkie/tools/log.h"
#include "junkie/tools/miscmacs.h"
#include "junkie/tools/objalloc.h"
#include "junkie/tools/timeval.h"
#include "junkie/tools/queue.h"
#include "junkie/tools/ext.h"
#include "junkie/proto/cap.h"   // for collapse_ifaces
#include "junkie/proto/eth.h"   // for collapse_vlans
#include "junkie/proto/deduplication.h"
#include "junkie/cpp.h"
#include "hook.h"

LOG_CATEGORY_DEF(digest);
#undef LOG_CAT
#define LOG_CAT digest_log_category

// Hooks for each (non-)dup.
HOOK(dup);

unsigned max_dup_delay = 100000; // microseconds
EXT_PARAM_RW(max_dup_delay, "max-dup-delay", uint, "Number of microseconds between two packets that can not be duplicates (set to 0 to disable deduplication altogether)")

static unsigned fast_dedup_duration = 10000000;    // microseconds
EXT_PARAM_RW(fast_dedup_duration, "fast-dedup-duration", uint, "Number of microseconds between two phases of comprehensive deduplication");

static double fast_dedup_distance = 2.;
EXT_PARAM_RW(fast_dedup_distance, "fast-dedup-distance", double, "How many sigmas beyond average dup DT should we search for dups in fast dedup phases");

static LIST_HEAD(digest_queues, digest_queue) digest_queues;    // FIXME: Please do not share me with other threads!

/*
 * Individual digest (digest_qcell)
 */

struct digest_qcell {
    TAILQ_ENTRY(digest_qcell) entry;
    unsigned char digest[DIGEST_SIZE];
    struct timeval tv;
};

// Caller must own q->mutex
static void digest_qcell_ctor(struct digest_qcell *qc, struct digest_queue_ *q, struct timeval const *tv)
{
    qc->tv = *tv;
    q->length ++;
    TAILQ_INSERT_HEAD(&q->qcells, qc, entry);
}

// Note: there is no qcell_new since the qcell is allocated before construction to avoid copying the digest

// Caller must own q->mutex
static void digest_qcell_dtor(struct digest_qcell *qc, struct digest_queue_ *q)
{
    assert(q->length > 0);
    q->length --;
    TAILQ_REMOVE(&q->qcells, qc, entry);
}

// Caller must own q->mutex
static void digest_qcell_del(struct digest_qcell *qc, struct digest_queue_ *q)
{
    digest_qcell_dtor(qc, q);
    objfree(qc);
}

static void reset_digests(struct digest_queue *dq)
{
    for (unsigned i = 0; i < NB_ELEMS(dq->queues); i++) {
        struct digest_queue_ *const q = dq->queues + i;
        mutex_lock(&q->mutex);
        struct digest_qcell *qc;
        while (NULL != (qc = TAILQ_FIRST(&q->qcells))) {
            digest_qcell_del(qc, q);
        }
        mutex_unlock(&q->mutex);
    }
}

/*
 * Digest queues
 */

static void digest_queue_del_by_ref(struct ref *);

static void digest_queue_ctor(struct digest_queue *dq, uint8_t dev_id)
{
    for (unsigned i = 0; i < NB_ELEMS(dq->queues); i++) {
        struct digest_queue_ *const q = dq->queues + i;

        mutex_ctor(&q->mutex, "digest queue");
        TAILQ_INIT(&q->qcells);
        q->length = 0;
        q->comprehensive = true;
        timeval_reset(&q->period_start);    // will be set later with TS of first packet
        q->dt_sum = q->dt_sum2 = 0;
        q->nb_dups = 0;
        // defer initialization of max_dt until the first packet is met so that the user has a chance to set initial max_dup_delay from cmd line (useful for tests)
    }

    dq->dev_id = dev_id;

    ref_ctor(&dq->ref, digest_queue_del_by_ref);

    LIST_INSERT_HEAD(&digest_queues, dq, entry);
}

static struct digest_queue *digest_queue_new(uint8_t dev_id)
{
    struct digest_queue *dq = objalloc(sizeof(*dq), "digest_queue");
    if (dq) digest_queue_ctor(dq, dev_id);
    return dq;
}

static void digest_queue_dtor(struct digest_queue *dq)
{
    LIST_REMOVE(dq, entry);

    reset_digests(dq);
    for (unsigned i = 0; i < NB_ELEMS(dq->queues); i++) {
        struct digest_queue_ *const q = dq->queues + i;
        mutex_dtor(&q->mutex);
    }

    ref_dtor(&dq->ref);
}

static void digest_queue_del(struct digest_queue *dq)
{
    digest_queue_dtor(dq);
    objfree(dq);
}

static void digest_queue_del_by_ref(struct ref *ref)
{
    struct digest_queue *dq = DOWNCAST(ref, ref, digest_queue);
    digest_queue_del(dq);
}

struct digest_queue *digest_queue_unref(struct digest_queue *dq)
{
    return unref(&dq->ref);
}

struct digest_queue *digest_queue_get(uint8_t dev_id)
{
    struct digest_queue *dq;
    LIST_LOOKUP(dq, &digest_queues, entry, dq->dev_id == dev_id);
    if (dq) return ref(&dq->ref);

    return digest_queue_new(dev_id);
}

/*
 * Stats
 */

static void reset_dedup_stats(void)
{
    struct digest_queue *dq;
    LIST_FOREACH(dq, &digest_queues, entry) {
        dq->nb_dup_found = dq->nb_nodup_found = 0;
    }
}

// caller must own nb_digests lock
static void update_dedup_stats(struct digest_queue *dq, unsigned dup_found, unsigned nodup_found)
{
    uint64_t d, nd;
#   ifdef __GNUC__
    d  = __sync_add_and_fetch(&dq->nb_dup_found, dup_found);
    nd = __sync_add_and_fetch(&dq->nb_nodup_found, nodup_found);
#   else
    d  = (dq->nb_dup_found += dup_found);
    nd = (dq->nb_nodup_found += nodup_found);
#   endif

    if (d == UINT_LEAST64_MAX || nd == UINT_LEAST64_MAX) {  // fail! unsafe. But these are user stats
        dq->nb_dup_found >>= 1;
        dq->nb_nodup_found >>= 1;
    }
}

/*
 * Digest Queue
 */

static void digest_frame(unsigned char buf[DIGEST_SIZE], size_t size, uint8_t *restrict packet)
{
#   define BUFSIZE_TO_HASH 64

#   define ETHER_DST_ADDR_OFFSET   0
#   define ETHER_SRC_ADDR_OFFSET   ETHER_DST_ADDR_OFFSET + 6
#   define ETHER_ETHERTYPE_OFFSET  ETHER_SRC_ADDR_OFFSET + 6
#   define ETHER_HEADER_SIZE       ETHER_ETHERTYPE_OFFSET + 2

#   define IPV4_VERSION_OFFSET     0
#   define IPV4_TOS_OFFSET         IPV4_VERSION_OFFSET + 1
#   define IPV4_LEN_OFFSET         IPV4_TOS_OFFSET + 1
#   define IPV4_ID_OFFSET          IPV4_LEN_OFFSET + 2
#   define IPV4_OFF_OFFSET         IPV4_ID_OFFSET + 2
#   define IPV4_TTL_OFFSET         IPV4_OFF_OFFSET + 2
#   define IPV4_PROTO_OFFSET       IPV4_TTL_OFFSET + 1
#   define IPV4_CHECKSUM_OFFSET    IPV4_PROTO_OFFSET + 1
#   define IPV4_SRC_HOST_OFFSET    IPV4_CHECKSUM_OFFSET + 2
#   define IPV4_DST_HOST_OFFSET    IPV4_SRC_HOST_OFFSET + 4

    SLOG(LOG_DEBUG, "Compute the digest of %zu bytes frame", size);

    unsigned iphdr_offset = ETHER_HEADER_SIZE;
    unsigned ethertype_offset = ETHER_ETHERTYPE_OFFSET;
    unsigned hash_start = iphdr_offset;

    if (
        size > ethertype_offset + 1 &&
        0x00 == packet[ethertype_offset] &&
        0x00 == packet[ethertype_offset+1]
    ) {  // Skip Linux Cooked Capture special header
        iphdr_offset += 2;
        ethertype_offset += 2;
        hash_start += 2;
    }

    if (
        size >= ethertype_offset+1 &&
        0x81 == packet[ethertype_offset] &&
        0x00 == packet[ethertype_offset+1]
    ) { // Optionally skip the VLan Tag
        iphdr_offset += 4;
        if (collapse_vlans) hash_start += 4;
    }

    /* If size is 64 bytes or below, assume trailing zeros are Ethernet padding.
     * We'd rather does this as parsing Eth header + IP to figure out
     * the actual payload size, since it's simpler, faster and works for any payload type.
     */
    if (size <= 64) {
        while (size > 0 && packet[size-1] == 0) size--;
    }

    if (size < iphdr_offset + IPV4_CHECKSUM_OFFSET) {
        SLOG(LOG_DEBUG, "Small frame (%zu bytes), compute the digest on the whole data", size);
        ASSERT_COMPILE(sizeof(uint8_t) == 1);
        (void)MD4((unsigned char *)packet, size, buf);
        return;
    }

    assert(size >= iphdr_offset + IPV4_TOS_OFFSET);
    assert(size >= iphdr_offset + IPV4_TTL_OFFSET);
    uint8_t tos = packet[iphdr_offset + IPV4_TOS_OFFSET];
    uint8_t ttl = packet[iphdr_offset + IPV4_TTL_OFFSET];
    uint16_t checksum = READ_U16(&packet[iphdr_offset + IPV4_CHECKSUM_OFFSET]);

    uint8_t ipversion = (packet[iphdr_offset + IPV4_VERSION_OFFSET] & 0xf0) >> 4;
    if (4 == ipversion) {
        // We must mask different fields which may be rewritten by
        // network equipment (routers, switches, etc), eg. TTL, Diffserv
        // or IP Header Checksum
        packet[iphdr_offset + IPV4_TOS_OFFSET] = 0x00;
        packet[iphdr_offset + IPV4_TTL_OFFSET] = 0x00;
        memset(packet + iphdr_offset + IPV4_CHECKSUM_OFFSET, 0, sizeof(uint16_t));
    }

    size_t const len = MIN(BUFSIZE_TO_HASH, size - hash_start);
    (void)MD4((unsigned char *)&packet[hash_start], len, buf);

    if (4 == ipversion) {
        // Restore the dumped IP header fields
        packet[iphdr_offset + IPV4_TOS_OFFSET] = tos;
        packet[iphdr_offset + IPV4_TTL_OFFSET] = ttl;
        memcpy(packet + iphdr_offset + IPV4_CHECKSUM_OFFSET, &checksum, sizeof checksum);
    }
}

// This computes the dt_max that will be used in the fast_dedup phase
// (called at the end of the comprehensive dedup phase).
// We merely blur the new instantaneous dt_max with the previous one.
// Caller must own q->mutex
static unsigned new_avg_dt_max(struct digest_queue_ *q, unsigned dt)
{
    uint_least64_t const old = q->dt_max;
    uint_least64_t const new = dt;
    return MIN((old+old+old+new)>>2, max_dup_delay);
}

bool digest_queue_find(struct digest_queue *dq, size_t cap_len, uint8_t *packet, struct timeval const *frame_tv)
{
    if (! max_dup_delay) return false;

    // We allocate digest here and will reuse this memory if we keep it (likely).
    struct digest_qcell *qc_new = objalloc(sizeof(*qc_new), "digest");
    digest_frame(qc_new->digest, cap_len, packet);

    unsigned const h = qc_new->digest[0] % NB_ELEMS(dq->queues);
    struct digest_queue_ *const q = dq->queues + h;

    mutex_lock(&q->mutex);

    struct timeval min_tv = *frame_tv;
    timeval_sub_usec(&min_tv, max_dup_delay);
    // min_tv is now set to minimal TS for a packet we want to consider for dup detection.

    // First of all, delete the old qcells
    struct digest_qcell *qc;
    while (NULL != (qc = TAILQ_LAST(&q->qcells, qcells))) {
        if (timeval_cmp(&qc->tv, &min_tv) > 0) break;
        digest_qcell_del(qc, q);
    }

    // set min_tv to the min TS we want to check at this run
    if (q->comprehensive) {
        if (! timeval_is_set(&q->period_start)) {
            q->period_start = *frame_tv;
            q->dt_max = max_dup_delay;
        } else if (timeval_sub(frame_tv, &q->period_start) >= 2 * max_dup_delay) {
            // leave comprehensive mode if we are doing it for more than 2*max_dup_delay
            SLOG(LOG_INFO, "dev=%"PRIu8",queue[%u]: Leaving comprehensive deduplication since we got from %s to %s", dq->dev_id, h, timeval_2_str(&q->period_start), timeval_2_str(frame_tv));
            if (q->nb_dups == 0) {
                // Wow, no dups at all?!
                q->dt_max = new_avg_dt_max(q, 0);  // welcome in the autobahn!
            } else {
                uint64_t const avg = (q->dt_sum + (q->nb_dups>>1)) / q->nb_dups;
                uint64_t const sigma = q->nb_dups > 1 ? sqrt((q->dt_sum2 + (q->nb_dups>>1)) / q->nb_dups - avg*avg) : avg/2;
                uint64_t const dt_max = 1U + avg + fast_dedup_distance * sigma;
                q->dt_max = new_avg_dt_max(q, dt_max);
                SLOG(LOG_DEBUG, "dev=%"PRIu8",queue[%u]: New dt_max=%uus, since nb_dups=%u, dt_sum=%"PRId64"us, dt_sum2=%"PRId64"us2 -> avg=%"PRId64"us, sigma=%"PRId64"us", dq->dev_id, h, q->dt_max, q->nb_dups, q->dt_sum, q->dt_sum2, avg, sigma);
            }
            q->comprehensive = false;
        }
    }

    if (! q->comprehensive) {
        // Enter comprehensive mode once in a while
        if (timeval_sub(frame_tv, &q->period_start) >= MAX(2*max_dup_delay, fast_dedup_duration)) {
            SLOG(LOG_INFO, "dev=%"PRIu8",queue[%u]: Entering comprehensive deduplication", dq->dev_id, h);
            q->period_start = *frame_tv;
            q->dt_sum = q->dt_sum2 = 0;
            q->nb_dups = 0;
            q->dt_max = max_dup_delay;
            q->comprehensive = true;
        }
    }

    // we are going to look dt_max usecs in the past
    min_tv = *frame_tv;
    timeval_sub_usec(&min_tv, q->dt_max);

    unsigned count = 0;
    // now look all qcells for a dup
    TAILQ_FOREACH(qc, &q->qcells, entry) {  // loop over all cells from recent to old
        if (timeval_cmp(&qc->tv, &min_tv) < 0) {
            // too far back in time, this can't be a dup.
            SLOG(LOG_DEBUG, "dev=%"PRIu8",queue[%u]: Reached an old digest dating back to %s (while we limit ourself at %s, being at %s)", dq->dev_id, h, timeval_2_str(&qc->tv), timeval_2_str(&min_tv), timeval_2_str(frame_tv));
            break;
        } else if (
            0 == memcmp(qc->digest, qc_new->digest, DIGEST_SIZE)
        ) { // found a dup
            struct dedup_proto_info info;
            proto_info_ctor(&info.info, NULL /* hum */, NULL, 0, cap_len);
            SLOG(LOG_DEBUG, "dev=%"PRIu8",queue[%u]: Found a dup after %u/%u digests (max_dt=%uus)", dq->dev_id, h, count, q->length, q->dt_max);
            // Note that we do not promote the dup in order to avoid dup + dup + dup + retrans being interpreted as 4 dups.
            if (q->comprehensive) {
                info.dt = timeval_sub(frame_tv, &qc->tv);
                // update the infos
                q->dt_sum += llabs(info.dt);
                q->dt_sum2 += info.dt*info.dt;
                q->nb_dups ++;
            }

            update_dedup_stats(dq, 1, 0);
            mutex_unlock(&q->mutex);
            objfree(qc_new);
            dup_subscribers_call(&info.info, cap_len, packet, frame_tv);
            return true;
        }
        count ++;
    }

    // Here we have no dup thus we must store qc_new
    SLOG(LOG_DEBUG, "dev=%"PRIu8",queue[%u]: No dup found after %u/%u digests (max_dt=%uus)", dq->dev_id, h, count, q->length, q->dt_max);
    update_dedup_stats(dq, 0, 1);
    digest_qcell_ctor(qc_new, q, frame_tv);
    mutex_unlock(&q->mutex);
    return false;
}

/*
 * Extensions
 */

static SCM dup_found_sym;
static SCM nodup_found_sym;
static SCM queue_len_sym;
static SCM delta_queue_len_sym;
static SCM dt_sym;
static SCM delta_dt_sym;

static struct ext_function sg_dedup_stats;
static SCM g_dedup_stats(SCM dev_id_)
{
    uint8_t dev_id = scm_to_uint8(dev_id_);
    struct digest_queue *dq;
    LIST_LOOKUP(dq, &digest_queues, entry, dq->dev_id == dev_id);
    if (! dq) return SCM_BOOL_F;

    // Compute avgs/delta on all queues
    unsigned max_dt_max = 0;
    unsigned min_dt_max = UINT_MAX;
    unsigned queue_len_sum = 0;
    unsigned queue_len_count = 0;
    unsigned max_queue_len = 0;
    unsigned min_queue_len = UINT_MAX;
    unsigned dt_max_sum = 0;
    unsigned dt_max_count = 0;

    for (unsigned i = 0; i < NB_ELEMS(dq->queues); i++) {
        struct digest_queue_ *const q = dq->queues + i;
        mutex_lock(&q->mutex);
        queue_len_sum += q->length;
        if (q->length > max_queue_len) max_queue_len = q->length;
        if (q->length < min_queue_len) min_queue_len = q->length;
        queue_len_count ++;
        if (timeval_is_set(&q->period_start) && ! q->comprehensive) {
            SLOG(LOG_INFO, "dev=%"PRIu8",queue[%u]: dt_max = %uus, queue_len = %u", dev_id, i, q->dt_max, q->length);
            dt_max_sum += q->dt_max;
            if (q->dt_max > max_dt_max) max_dt_max = q->dt_max;
            if (q->dt_max < min_dt_max) min_dt_max = q->dt_max;
            dt_max_count ++;
        }
        mutex_unlock(&q->mutex);
    }

    unsigned const avg_queue_len = queue_len_count ? queue_len_sum / queue_len_count : 0;
    unsigned const avg_dt_max = dt_max_count ? dt_max_sum / dt_max_count : 0;
    SCM ret = scm_list_n(
        scm_cons(dup_found_sym,         scm_from_uint64(dq->nb_dup_found)),
        scm_cons(nodup_found_sym,       scm_from_uint64(dq->nb_nodup_found)),
        scm_cons(queue_len_sym,         scm_from_uint(avg_queue_len)),
        scm_cons(delta_queue_len_sym,   scm_from_uint(queue_len_count ? MAX(max_queue_len-avg_queue_len, avg_queue_len-min_queue_len) : 0)),
        scm_cons(dt_sym,                scm_from_uint(avg_dt_max)),
        scm_cons(delta_dt_sym,          scm_from_uint(dt_max_count ? MAX(max_dt_max-avg_dt_max, avg_dt_max-min_dt_max) : 0)),
        SCM_UNDEFINED);

    return ret;
}

static struct ext_function sg_reset_dedup_stats;
static SCM g_reset_dedup_stats(void)
{
    reset_dedup_stats();
    return SCM_UNSPECIFIED;
}

static struct ext_function sg_reset_digests;
static SCM g_reset_digests(void)
{
    struct digest_queue *dq;
    LIST_FOREACH(dq, &digest_queues, entry) {
        reset_digests(dq);
    }

    return SCM_UNSPECIFIED;
}

/*
 * Init
 */

static unsigned inited;
void digest_init(void)
{
    if (inited++) return;
    mutex_init();
    objalloc_init();
    ext_init();

    dup_found_sym       = scm_permanent_object(scm_from_latin1_symbol("dup-found"));
    nodup_found_sym     = scm_permanent_object(scm_from_latin1_symbol("nodup-found"));
    queue_len_sym       = scm_permanent_object(scm_from_latin1_symbol("avg-queue-len"));
    delta_queue_len_sym = scm_permanent_object(scm_from_latin1_symbol("delta-queue-len"));
    dt_sym              = scm_permanent_object(scm_from_latin1_symbol("avg-dt"));
    delta_dt_sym        = scm_permanent_object(scm_from_latin1_symbol("delta-dt"));

    log_category_digest_init();
    ext_param_max_dup_delay_init();
    ext_param_fast_dedup_duration_init();
    ext_param_fast_dedup_distance_init();

    LIST_INIT(&digest_queues);

    dup_hook_init();

    ext_function_ctor(&sg_dedup_stats,
        "deduplication-stats", 1, 0, 0, g_dedup_stats,
        "(deduplication-stats 1): return some statistics about the deduplication mechanism on device 1.\n"
        "See also (? 'reset-deduplication-stats).\n");

    ext_function_ctor(&sg_reset_dedup_stats,
        "reset-deduplication-stats", 0, 0, 0, g_reset_dedup_stats,
        "(reset-deduplication-stats): does what the name suggest.\n"
        "You probably already know (? 'deduplication-stats).\n");

    ext_function_ctor(&sg_reset_digests,
        "reset-digests", 0, 0, 0, g_reset_digests,
        "(reset-digests): clear all stored digests. Usefull when testing.\n");
}

void digest_fini(void)
{
    if (--inited) return;

    dup_hook_fini();

    struct digest_queue *q;
    while (NULL != (q = LIST_FIRST(&digest_queues))) {
        digest_queue_del(q);
    }

    ext_param_fast_dedup_distance_fini();
    ext_param_fast_dedup_duration_fini();
    ext_param_max_dup_delay_fini();
    log_category_digest_fini();

    ext_fini();
    objalloc_fini();
    mutex_fini();
}
