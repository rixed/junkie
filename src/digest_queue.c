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
#include "junkie/tools/hash.h"
#include "junkie/proto/cap.h"   // for collapse_ifaces
#include "junkie/proto/eth.h"   // for collapse_vlans
#include "junkie/proto/deduplication.h"
#include "junkie/cpp.h"
#include "hook.h"

// We use directly the MD4 as a hash key
#undef HASH_FUNC
#define HASH_FUNC(key) ((key)->hash_key)

LOG_CATEGORY_DEF(digest);
#undef LOG_CAT
#define LOG_CAT digest_log_category

// Hooks for each (non-)dup.
HOOK(dup);

unsigned max_dup_delay = 100000; // microseconds
EXT_PARAM_RW(max_dup_delay, "max-dup-delay", uint, "Number of microseconds between two packets that can not be duplicates (set to 0 to disable deduplication altogether)")

static LIST_HEAD(digest_queues, digest_queue) digest_queues;    // FIXME: Please do not share me with other threads!

/*
 * Individual digest (digest_qcell)
 */

struct digest_qcell {
    HASH_ENTRY(digest_qcell) entry;
    union {
        unsigned char digest[DIGEST_SIZE];
        uint32_t hash_key;
    } u;
    struct timeval tv;
};

// Caller must own q->mutex
static void digest_qcell_ctor(struct digest_qcell *qc, struct digest_queue_ *q, struct timeval const *tv)
{
    qc->tv = *tv;
    HASH_INSERT(&q->qcells, qc, &qc->u, entry);
}

// Note: there is no qcell_new since the qcell is allocated before construction to avoid copying the digest

// Caller must own q->mutex
static void digest_qcell_dtor(struct digest_qcell *qc, struct digest_queue_ *q)
{
    HASH_REMOVE(&q->qcells, qc, entry);
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
        struct digest_qcell *qc, *tmp;
        HASH_FOREACH_SAFE(qc, &q->qcells, entry, tmp) {
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
    SLOG(LOG_DEBUG, "Constructing digest_queue@%p for dev_id=%"PRIu8, dq, dev_id);

    for (unsigned i = 0; i < NB_ELEMS(dq->queues); i++) {
        struct digest_queue_ *const q = dq->queues + i;

        mutex_ctor(&q->mutex, "digest queue");
        HASH_INIT(&q->qcells, 1024, "digest queue");
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
    SLOG(LOG_DEBUG, "Destructing digest_queue@%p", dq);

    LIST_REMOVE(dq, entry);

    reset_digests(dq);
    for (unsigned i = 0; i < NB_ELEMS(dq->queues); i++) {
        struct digest_queue_ *const q = dq->queues + i;
        mutex_dtor(&q->mutex);
        HASH_DEINIT(&q->qcells);
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

void digest_queue_unref(struct digest_queue **dq)
{
    if (! *dq) return;
    unref(&(*dq)->ref);
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

static void incr_dup(struct digest_queue *dq)
{
#   ifdef __GNUC__
    __sync_add_and_fetch(&dq->nb_dup_found, 1);
#   else
    dq->nb_dup_found ++;
#   endif
    // as nb_dup_found is 64 bits we don't fear a wrap around
}

static void incr_nodup(struct digest_queue *dq)
{
#   ifdef __GNUC__
    __sync_add_and_fetch(&dq->nb_nodup_found, 1);
#   else
    dq->nb_nodup_found ++;
#   endif
    // as nb_nodup_found is 64 bits we don't fear a wrap around
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

bool digest_queue_find(struct digest_queue *dq, size_t cap_len, uint8_t *packet, struct timeval const *frame_tv)
{
    if (! max_dup_delay) return false;

    // We allocate digest here and will reuse this memory if we keep it (likely).
    struct digest_qcell *qc_new = objalloc(sizeof(*qc_new), "digest");
    digest_frame(qc_new->u.digest, cap_len, packet);

    unsigned const h = qc_new->u.digest[8] % NB_ELEMS(dq->queues);
    struct digest_queue_ *const q = dq->queues + h;

    mutex_lock(&q->mutex);

    struct timeval min_tv = *frame_tv;
    timeval_sub_usec(&min_tv, max_dup_delay);
    // min_tv is set to minimal TS for a packet we want to consider for dup detection.
    struct digest_qcell *qc, *qc_tmp;

    unsigned count = 0;
    // now look all qcells for a dup
    HASH_FOREACH_SAME_KEY_SAFE(qc, &q->qcells, &qc_new->u, u, entry, qc_tmp) {
        // timeout first (so that retransmissions are elimiated)
        if (timeval_cmp(&qc->tv, &min_tv) < 0) {
            digest_qcell_del(qc, q);
        } else if (0 == memcmp(qc->u.digest, qc_new->u.digest, DIGEST_SIZE)) {
            // found a dup
            struct dedup_proto_info info;
            proto_info_ctor(&info.info, NULL /* hum */, NULL, 0, cap_len);
            SLOG(LOG_DEBUG, "dev=%"PRIu8",queue[%u]: Found a dup after %u", dq->dev_id, h, count);
            // Note that we do not promote the dup in order to avoid dup + dup + dup + retrans being interpreted as 4 dups.
            info.dt = llabs(timeval_sub(frame_tv, &qc->tv));
            incr_dup(dq);
            mutex_unlock(&q->mutex);
            objfree(qc_new);
            dup_subscribers_call(&info.info, cap_len, packet, frame_tv);
            return true;
        }
        count ++;
    }

    // Here we have no dup thus we must store qc_new
    SLOG(LOG_DEBUG, "dev=%"PRIu8",queue[%u]: No dup found after %u", dq->dev_id, h, count);
    incr_nodup(dq);
    digest_qcell_ctor(qc_new, q, frame_tv);
    mutex_unlock(&q->mutex);
    return false;
}

/*
 * Extensions
 */

static SCM dup_found_sym;
static SCM nodup_found_sym;

static struct ext_function sg_dedup_stats;
static SCM g_dedup_stats(SCM dev_id_)
{
    uint8_t dev_id = scm_to_uint8(dev_id_);
    struct digest_queue *dq;
    LIST_LOOKUP(dq, &digest_queues, entry, dq->dev_id == dev_id);
    if (! dq) return SCM_BOOL_F;

    SCM ret = scm_list_2(
        scm_cons(dup_found_sym,         scm_from_uint64(dq->nb_dup_found)),
        scm_cons(nodup_found_sym,       scm_from_uint64(dq->nb_nodup_found)));

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
    hash_init();

    dup_found_sym       = scm_permanent_object(scm_from_latin1_symbol("dup-found"));
    nodup_found_sym     = scm_permanent_object(scm_from_latin1_symbol("nodup-found"));

    log_category_digest_init();
    ext_param_max_dup_delay_init();

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

    doomer_run();
    assert(LIST_EMPTY(&digest_queues));

    ext_param_max_dup_delay_fini();
    log_category_digest_fini();

    hash_fini();
    ext_fini();
    objalloc_fini();
    mutex_fini();
}
