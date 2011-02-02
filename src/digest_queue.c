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
#include <inttypes.h>
#include <openssl/md5.h>
#include <junkie/tools/log.h>
#include <junkie/tools/miscmacs.h>
#include <junkie/tools/mallocer.h>
#include <junkie/cpp.h>
#include "digest_queue.h"

static char const Id[] = "$Id$";

MALLOCER_DEF(digest_queues);

static int digest_queue_ctor(struct digest_queue *q, unsigned size)
{
    q->idx = 0;
    q->size = size;
    q->digests = MALLOC(digest_queues, q->size * sizeof *q->digests);
    if (! q->digests) return -1;
    memset(q->digests, 0, q->size * sizeof q->digests);

    return 0;
}

struct digest_queue *digest_queue_new(unsigned size)
{
    MALLOCER_INIT(digest_queues);
    struct digest_queue *q = MALLOC(digest_queues, sizeof(*q));
    if (! q) return NULL;

    if (0 != digest_queue_ctor(q, size)) {
        FREE(q);
        return NULL;
    }

    return q;
}

static void digest_queue_dtor(struct digest_queue *q)
{
    FREE(q->digests);
}

void digest_queue_del(struct digest_queue *q)
{
    digest_queue_dtor(q);
    FREE(q);
}

void digest_queue_push(struct digest_queue *q, uint8_t digest[DIGEST_SIZE], const struct frame *frm)
{
    q->idx = (q->idx + 1) % q->size;
    memcpy(q->digests[q->idx].digest, digest, DIGEST_SIZE);
    q->digests[q->idx].tv   = frm->tv;
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

void digest_frame(uint8_t *buf, struct frame *frm)
{
    SLOG(LOG_DEBUG, "Compute the md5 digest of relevant data in the frame");

    size_t iphdr_offset = ETHER_HEADER_SIZE;
    size_t ethertype_offset = ETHER_ETHERTYPE_OFFSET;

    if (frm->cap_len >= ethertype_offset && *(uint16_t *)&frm->data[ethertype_offset] == 0x0000) {  // Skip Linux Cooked Capture special header
        iphdr_offset += 2;
        ethertype_offset += 2;
    }

    if (frm->cap_len >= ethertype_offset+1 && 0x81 == frm->data[ethertype_offset] && 0x00 == frm->data[ethertype_offset+1]) {
        iphdr_offset += 4;
    }

    if (frm->cap_len < iphdr_offset + IPV4_CHECKSUM_OFFSET) {
        SLOG(LOG_DEBUG, "Small frame (%zu bytes), compute the digest on the whole data", frm->cap_len);
        (void) MD5((unsigned char *)frm->data, frm->cap_len, buf);
        return;
    }

    size_t len = MIN(BUFSIZE_TO_HASH, frm->cap_len - iphdr_offset);

    assert(frm->cap_len >= iphdr_offset + IPV4_TOS_OFFSET);
    assert(frm->cap_len >= iphdr_offset + IPV4_TTL_OFFSET);
    uint8_t tos = frm->data[iphdr_offset + IPV4_TOS_OFFSET];
    uint8_t ttl = frm->data[iphdr_offset + IPV4_TTL_OFFSET];
    uint16_t checksum = *(uint16_t *)&frm->data[iphdr_offset + IPV4_CHECKSUM_OFFSET];

    uint8_t ipversion = (frm->data[iphdr_offset + IPV4_VERSION_OFFSET] & 0xf0) >> 4;
    if (4 == ipversion) {
        // We must mask different fields which may be rewritten by
        // network equipment (routers, switches, etc), eg. TTL, Diffserv
        // or IP Header Checksum
        frm->data[iphdr_offset + IPV4_TOS_OFFSET] = 0x00;
        frm->data[iphdr_offset + IPV4_TTL_OFFSET] = 0x00;
        memset(frm->data + iphdr_offset + IPV4_CHECKSUM_OFFSET, 0, sizeof(uint16_t));
    }

    (void) MD5((unsigned char *)&frm->data[iphdr_offset], len, buf);

    if (4 == ipversion) {
        // Restore the dumped IP header fields
        frm->data[iphdr_offset + IPV4_TOS_OFFSET] = tos;
        frm->data[iphdr_offset + IPV4_TTL_OFFSET] = ttl;
        memcpy(frm->data + iphdr_offset + IPV4_CHECKSUM_OFFSET, &checksum, sizeof checksum);
    }
}
