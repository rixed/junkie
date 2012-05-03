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
#include <sys/time.h>
#include <assert.h>
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

#define NB_QUEUES (CPU_MAX < 256 ? CPU_MAX : 256)   /* Must not be greater that 256 since we use only one byte from digest to hash */
static struct digest_queue {
    struct queue {
        struct digest_qcell {
            unsigned char digest[DIGEST_SIZE];
            struct timeval tv;
            uint8_t dev_id; // The device this packet was recieved from
        } *digests;
        unsigned idx;       // Index of the lastly added frame (more recent)
        unsigned length;    // Actually all queues have the same length, except during resizing
        struct mutex mutex;
    } queues[NB_QUEUES];    // The queue is chosen according to digest hash, so that several distinct threads can perform lookups simultaneously.
} *digests;

static int dup_detection_delay = 50000;  // microseconds
EXT_PARAM_RW(dup_detection_delay, "dup-detection-delay", int, "Number of microseconds between two packets that can't be duplicates")

// Some stats about the use of the digest queue. Protected with nb_digests lock.
static uint_least64_t nb_dup_found, nb_nodup_found, nb_eol_found;

static void reset_dedup_stats(void)
{
    nb_dup_found = nb_nodup_found = nb_eol_found = 0;
}

static int digest_queue_resize(unsigned length)
{
    for (unsigned i = 0; i < NB_ELEMS(digests->queues); i++) {
        struct queue *const q = digests->queues + i;

        void *new = objalloc(length * sizeof *q->digests, "pkt digests");
        if (! new && length > 0) return -1;

        mutex_lock(&q->mutex);
        if (q->digests) objfree(q->digests);
        q->digests = new;
        q->idx = 0;
        q->length = length;
        if (q->digests) memset(q->digests, 0, q->length * sizeof q->digests);
        mutex_unlock(&q->mutex);
    }

    return 0;
}

static unsigned nb_digests = 2000;
// The seter is a little special as it rebuild the digest queue
static struct ext_param ext_param_nb_digests;   // This lock protects the deduplication process globally (see frame_mirror_drop)
static SCM g_ext_param_set_nb_digests(SCM v)
{
    SCM ret = SCM_BOOL_F;
    SLOG(LOG_DEBUG, "Setting value for nb_digests");
    assert(&ext_param_nb_digests.bound);
    scm_dynwind_begin(0);
    pthread_mutex_lock(&ext_param_nb_digests.mutex);
    scm_dynwind_unwind_handler(pthread_mutex_unlock_, &ext_param_nb_digests.mutex, SCM_F_WIND_EXPLICITLY);

    unsigned new_nb_digests = scm_to_uint(v);
    if (0 == digest_queue_resize(new_nb_digests)) {
        nb_digests = new_nb_digests;
        ret = SCM_BOOL_T;
    }
    scm_dynwind_end();
    return ret;
}
EXT_PARAM_GET(nb_digests, uint)
EXT_PARAM_STRUCT_RW(nb_digests, "nb-digests", "How many digests do we keep for deduplication")
EXT_PARAM_CTORDTOR(nb_digests)

/*
 * Queue object
 */

static int digest_queue_ctor(struct digest_queue *digest, unsigned length)
{
    for (unsigned i = 0; i < NB_ELEMS(digest->queues); i++) {
        struct queue *const q = digest->queues + i;
        q->idx = 0;
        q->length = length;
        q->digests = objalloc(q->length * sizeof(*q->digests), "pkt digests");
        if (! q->digests && length > 0) return -1;
        if (q->digests) memset(q->digests, 0, q->length * sizeof q->digests);
        mutex_ctor(&q->mutex, "digest queue");
    }

    return 0;
}

static struct digest_queue *digest_queue_new(unsigned length)
{
    struct digest_queue *digest = objalloc(sizeof(*digest), "pkt digest queues");
    if (! digest) return NULL;

    if (0 != digest_queue_ctor(digest, length)) {
        objfree(digest);
        return NULL;
    }

    return digest;
}

static void digest_queue_dtor(struct digest_queue *digest)
{
    for (unsigned i = 0; i < NB_ELEMS(digest->queues); i++) {
        if (digest->queues[i].digests) objfree(digest->queues[i].digests);
        mutex_dtor(&digest->queues[i].mutex);
    }
}

static void digest_queue_del(struct digest_queue *digest)
{
    digest_queue_dtor(digest);
    objfree(digest);
}

#define BUFSIZE_TO_HASH 64

#define ETHER_DST_ADDR_OFFSET   0
#define ETHER_SRC_ADDR_OFFSET   ETHER_DST_ADDR_OFFSET + 6
#define ETHER_ETHERTYPE_OFFSET  ETHER_SRC_ADDR_OFFSET + 6
#define ETHER_HEADER_SIZE       ETHER_ETHERTYPE_OFFSET + 2

#define IPV4_VERSION_OFFSET     0
#define IPV4_TOS_OFFSET         IPV4_VERSION_OFFSET + 1
#define IPV4_LEN_OFFSET         IPV4_TOS_OFFSET + 1
#define IPV4_ID_OFFSET          IPV4_LEN_OFFSET + 2
#define IPV4_OFF_OFFSET         IPV4_ID_OFFSET + 2
#define IPV4_TTL_OFFSET         IPV4_OFF_OFFSET + 2
#define IPV4_PROTO_OFFSET       IPV4_TTL_OFFSET + 1
#define IPV4_CHECKSUM_OFFSET    IPV4_PROTO_OFFSET + 1
#define IPV4_SRC_HOST_OFFSET    IPV4_CHECKSUM_OFFSET + 2
#define IPV4_DST_HOST_OFFSET    IPV4_SRC_HOST_OFFSET + 4

static void digest_frame(unsigned char buf[DIGEST_SIZE], size_t size, uint8_t *restrict packet)
{
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

// caller must own nb_digests lock
static void update_dedup_stats(unsigned dup_found, unsigned nodup_found, unsigned eol_found)
{
    nb_dup_found += dup_found;
    nb_nodup_found += nodup_found;
    nb_eol_found += eol_found;
}

bool digest_queue_find(size_t cap_len, uint8_t *packet, uint8_t dev_id, struct timeval const *frame_tv)
{
    if (! dup_detection_delay) return false;

    uint8_t buf[DIGEST_SIZE];
    digest_frame(buf, cap_len, packet);

    struct timeval min_tv = *frame_tv;
    timeval_sub_usec(&min_tv, dup_detection_delay);
    unsigned const h = buf[0] % NB_ELEMS(digests->queues);
    struct queue *const q = digests->queues + h;

    mutex_lock(&q->mutex);

    unsigned i = q->length;
    if (q->length > 0) {
        do {
            unsigned j = (q->idx + i) % q->length;

            if (!timeval_is_set(&q->digests[j].tv) || timeval_cmp(&q->digests[j].tv, &min_tv) < 0) break;

            if (
                (collapse_ifaces || dev_id == q->digests[j].dev_id) &&
                0 == memcmp(q->digests[j].digest, buf, DIGEST_SIZE)
            ) {
                mutex_unlock(&q->mutex);
                update_dedup_stats(1, 0, 0);
                return true;
            }
        } while (--i);

        q->idx = (q->idx + 1) % q->length;
        memcpy(q->digests[q->idx].digest, buf, DIGEST_SIZE);
        q->digests[q->idx].tv = *frame_tv;
        q->digests[q->idx].dev_id = dev_id;
    }

    mutex_unlock(&q->mutex);
    if (i != 0) {
        update_dedup_stats(0, 1, 0);
    } else {
        update_dedup_stats(0, 0, 1);
    }
    return false;
}

/*
 * Extensions
 */

static SCM dup_found_sym;
static SCM nodup_found_sym;
static SCM end_of_list_found_sym;

static struct ext_function sg_dedup_stats;
static SCM g_dedup_stats(void)
{
    EXT_LOCK(nb_digests);
    SCM ret = scm_list_3(
        scm_cons(dup_found_sym,         scm_from_uint64(nb_dup_found)),
        scm_cons(nodup_found_sym,       scm_from_uint64(nb_nodup_found)),
        scm_cons(end_of_list_found_sym, scm_from_uint64(nb_eol_found)));
    EXT_UNLOCK(nb_digests);

    return ret;
}

static struct ext_function sg_reset_dedup_stats;
static SCM g_reset_dedup_stats(void)
{
    reset_dedup_stats();
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
    end_of_list_found_sym = scm_permanent_object(scm_from_latin1_symbol("end-of-list-found"));

    log_category_digest_init();
    ext_param_dup_detection_delay_init();
    ext_param_nb_digests_init();

    EXT_LOCK(nb_digests);
    digests = digest_queue_new(nb_digests);
    if (! digests) nb_digests = 0;
    EXT_UNLOCK(nb_digests);

    ext_function_ctor(&sg_dedup_stats,
        "deduplication-stats", 0, 0, 0, g_dedup_stats,
        "(deduplication-stats): return some statistics about the deduplication mechanism.\n"
        "See also (? 'reset-deduplication-stats).\n");

    ext_function_ctor(&sg_reset_dedup_stats,
        "reset-deduplication-stats", 0, 0, 0, g_reset_dedup_stats,
        "(reset-deduplication-stats): does what the name suggest.\n"
        "You probably already know (? 'deduplication-stats).\n");

}

void digest_fini(void)
{
    if (--inited) return;

    if (digests) {
        digest_queue_del(digests);
        digests = NULL;
    }

    ext_param_nb_digests_fini();
    ext_param_dup_detection_delay_fini();
    log_category_digest_fini();

    ext_fini();
    objalloc_fini();
    mutex_fini();
}
