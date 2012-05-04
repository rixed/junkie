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
#include "junkie/cpp.h"
#include "digest_queue.h"

#define DIGEST_SIZE MD4_DIGEST_LENGTH

LOG_CATEGORY_DEF(digest);
#undef LOG_CAT
#define LOG_CAT digest_log_category

struct qcell {
    TAILQ_ENTRY(qcell) entry;
    unsigned char digest[DIGEST_SIZE];
    struct timeval tv;
    uint8_t dev_id; // The device this packet was recieved from
};

#define NB_QUEUES (MIN(CPU_MAX, 256))   /* Must not be greater that 256 since we use only one byte from digest to hash */
static struct queue {
    struct mutex mutex; // protecting this queue
    // List of previously received packets, most recent first, ie loosely ordered according to frame timestamp
    TAILQ_HEAD(qcells, qcell) qcells;
    unsigned length;    // size of qcells list
    // Deduplication variables
    bool comprehensive; // make a comprehensive search for dups (otherwise look only up to dt_max)
    struct timeval period_start;    // start of the deduplication period
    uint64_t dt_sum, dt_sum2;   // sum of all dups dt and dt^2 (in ms not us!)
    unsigned dt_max;     // milliseconds! (only defined if period_start is set)
    unsigned nb_dups;
} queues[NB_QUEUES];    // The queue is chosen according to digest hash, so that several distinct threads can perform lookups simultaneously.

static unsigned max_dup_delay = 100; // milliseconds
EXT_PARAM_RW(max_dup_delay, "max-dup-delay", uint, "Number of milliseconds between two packets that can not be duplicates (set to 0 to disable deduplication altogether)")

static unsigned fast_dedup_duration = 10000;    // milliseconds
EXT_PARAM_RW(fast_dedup_duration, "fast-dedup-duration", uint, "Number of milliseconds between two phases of comprehensive deduplication");

static double fast_dedup_distance = 1.;
EXT_PARAM_RW(fast_dedup_distance, "fast-dedup-distance", double, "How many sigmas beyond average dup DT should we search for dups in fast dedup phases");

static void queue_ctor(struct queue *q)
{
    mutex_ctor(&q->mutex, "digest queue");
    TAILQ_INIT(&q->qcells);
    q->length = 0;
    q->comprehensive = true;
    timeval_reset(&q->period_start);    // will be set later with TS of first packet
    q->dt_sum = q->dt_sum2 = 0;
    q->nb_dups = 0;
    // defer initialization of max_dt until the first packet is met so that the user has a chance to set initial max_dup_delay from cmd line (usefull for tests)
}

/*
 * Stats
 */

// Some stats about the use of the digest queue. Unprotected by any lock.
static uint_least64_t nb_dup_found, nb_nodup_found;

static void reset_dedup_stats(void)
{
    nb_dup_found = nb_nodup_found = 0;
}

// caller must own nb_digests lock
static void update_dedup_stats(unsigned dup_found, unsigned nodup_found)
{
    uint64_t d, nd;
#   ifdef __GNUC__
    d  = __sync_add_and_fetch(&nb_dup_found, dup_found);
    nd = __sync_add_and_fetch(&nb_nodup_found, nodup_found);
#   else
    d  = (nb_dup_found += dup_found);
    nd = (nb_nodup_found += nodup_found);
#   endif

    if (d == UINT_LEAST64_MAX || nd == UINT_LEAST64_MAX) {
        nb_dup_found >>= 1;
        nb_nodup_found >>= 1;
    }
}

/*
 * Individual digest (qcell)
 */

// Caller must own q->mutex
static void qcell_ctor(struct qcell *qc, struct queue *q, struct timeval const *tv, uint8_t dev_id)
{
    qc->tv = *tv;
    qc->dev_id = dev_id;
    q->length ++;
    TAILQ_INSERT_HEAD(&q->qcells, qc, entry);
}

// Note: there is no qcell_new since the qcell is allocated before construction to avoid copying the digest

// Caller must own q->mutex
static void qcell_dtor(struct qcell *qc, struct queue *q)
{
    assert(q->length > 0);
    q->length --;
    TAILQ_REMOVE(&q->qcells, qc, entry);
}

// Caller must own q->mutex
static void qcell_del(struct qcell *qc, struct queue *q)
{
    qcell_dtor(qc, q);
    objfree(qc);
}

static void reset_digests(void)
{
    for (unsigned i = 0; i < NB_ELEMS(queues); i++) {
        struct queue *const q = queues + i;
        mutex_lock(&q->mutex);
        struct qcell *qc;
        while (NULL != (qc = TAILQ_FIRST(&q->qcells))) {
            qcell_del(qc, q);
        }
        mutex_unlock(&q->mutex);
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

bool digest_queue_find(size_t cap_len, uint8_t *packet, uint8_t dev_id, struct timeval const *frame_tv)
{
    if (! max_dup_delay) return false;

    struct qcell *qc_new = objalloc(sizeof(*qc_new), "digest");
    digest_frame(qc_new->digest, cap_len, packet);

    unsigned const h = qc_new->digest[0] % NB_ELEMS(queues);
    struct queue *const q = queues + h;

    mutex_lock(&q->mutex);

    struct timeval min_tv = *frame_tv;
    timeval_sub_msec(&min_tv, max_dup_delay);
    // min_tv is now set to minimal TS for a packet we want to keep for dup detection.

    // First of all, delete the old qcells
    struct qcell *qc;
    while (NULL != (qc = TAILQ_LAST(&q->qcells, qcells))) {
        if (timeval_cmp(&qc->tv, &min_tv) > 0) break;
        qcell_del(qc, q);
    }

    // set min_tv to the min TS we want to check at this run
    if (q->comprehensive) {
        if (! timeval_is_set(&q->period_start)) {
            q->period_start = *frame_tv;
            q->dt_max = max_dup_delay;
        } else if (timeval_sub(frame_tv, &q->period_start) >= 2 * 1000LL * max_dup_delay) {
            // leave comprehensive mode if we are doing it for more than 2*max_dup_delay
            SLOG(LOG_INFO, "queue[%u]: Leaving comprehensive deduplication since we got from %s to %s", h, timeval_2_str(&q->period_start), timeval_2_str(frame_tv));
            if (q->nb_dups == 0) {
                q->dt_max = 0;  // welcome in the autobahn!
            } else {
                int64_t const avg = q->dt_sum / q->nb_dups;
                int64_t const sigma = sqrt(avg*avg - (q->dt_sum2 / q->nb_dups));
                q->dt_max = avg + fast_dedup_distance * sigma;
                if (q->dt_max > max_dup_delay) SLOG(LOG_NOTICE, "queue[%u]: dt_max = %u > max_dup_delay = %u!", h, q->dt_max, max_dup_delay);
                SLOG(LOG_DEBUG, "queue[%u]: New dt_max=%u, since nb_dups=%u, dt_sum=%"PRId64", dt_sum2=%"PRId64" -> avg=%"PRId64", sigma=%"PRId64, h, q->dt_max, q->nb_dups, q->dt_sum, q->dt_sum2, avg, sigma);
            }
            q->comprehensive = false;
        }
    }

    if (! q->comprehensive) {
        // Enter comprehensive mode once in a while
        if (timeval_sub(frame_tv, &q->period_start) >= 1000LL * MAX(2*max_dup_delay, fast_dedup_duration)) {
            SLOG(LOG_INFO, "queue[%u]: Entering comprehensive deduplication", h);
            q->period_start = *frame_tv;
            q->dt_sum = q->dt_sum2 = 0;
            q->nb_dups = 0;
            q->dt_max = max_dup_delay;
            q->comprehensive = true;
        }
    }

    // we are going to look dt_max msecs in the past
    min_tv = *frame_tv;
    timeval_sub_msec(&min_tv, q->dt_max);

    unsigned count = 0;
    // now look all qcells for a dup
    TAILQ_FOREACH(qc, &q->qcells, entry) {  // loop over all cells from recent to old
        if (timeval_cmp(&qc->tv, &min_tv) < 0) {
            // too far back in time, this can't be a dup.
            SLOG(LOG_DEBUG, "queue[%u]: Reached an old digest dating back to %s (while we limit ourself at %s, being at %s)", h, timeval_2_str(&qc->tv), timeval_2_str(&min_tv), timeval_2_str(frame_tv));
            break;
        } else if (
            (collapse_ifaces || dev_id == qc->dev_id) &&
            0 == memcmp(qc->digest, qc_new->digest, DIGEST_SIZE)
        ) { // found a dup
            SLOG(LOG_DEBUG, "queue[%u]: Found a dup after %u/%u digests (max_dt=%ums)", h, count, q->length, q->dt_max);
            // Note that we do not promote the dup in order to avoid dup + dup + dup + retrans being interpreted as 4 dups.
            if (q->comprehensive) {
                int64_t const dt = timeval_sub(frame_tv, &qc->tv)/1000;
                // update the infos
                q->dt_sum += dt;
                q->dt_sum2 += dt*dt;
                q->nb_dups ++;
            }

            update_dedup_stats(1, 0);
            mutex_unlock(&q->mutex);
            objfree(qc_new);
            return true;
        }
        count ++;
    }

    // Here we have no dup thus we must store qc_new
    SLOG(LOG_DEBUG, "queue[%u]: No dup found after %u/%u digests (max_dt=%ums)", h, count, q->length, q->dt_max);
    update_dedup_stats(0, 1);
    qcell_ctor(qc_new, q, frame_tv, dev_id);
    mutex_unlock(&q->mutex);
    return false;
}

/*
 * Extensions
 */

static SCM dup_found_sym;
static SCM nodup_found_sym;

static struct ext_function sg_dedup_stats;
static SCM g_dedup_stats(void)
{
    SCM ret = scm_list_2(
        scm_cons(dup_found_sym,         scm_from_uint64(nb_dup_found)),
        scm_cons(nodup_found_sym,       scm_from_uint64(nb_nodup_found)));

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
    reset_digests();
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

    dup_found_sym         = scm_permanent_object(scm_from_latin1_symbol("dup-found"));
    nodup_found_sym       = scm_permanent_object(scm_from_latin1_symbol("nodup-found"));

    log_category_digest_init();
    ext_param_max_dup_delay_init();
    ext_param_fast_dedup_duration_init();
    ext_param_fast_dedup_distance_init();

    for (unsigned i = 0; i < NB_ELEMS(queues); i++) {
        queue_ctor(queues + i);
    }

    ext_function_ctor(&sg_dedup_stats,
        "deduplication-stats", 0, 0, 0, g_dedup_stats,
        "(deduplication-stats): return some statistics about the deduplication mechanism.\n"
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

    reset_digests();
    for (unsigned i = 0; i < NB_ELEMS(queues); i++) {
        struct queue *const q = queues + i;
        mutex_dtor(&q->mutex);
    }

    ext_param_fast_dedup_distance_fini();
    ext_param_fast_dedup_duration_fini();
    ext_param_max_dup_delay_fini();
    log_category_digest_fini();

    ext_fini();
    objalloc_fini();
    mutex_fini();
}
