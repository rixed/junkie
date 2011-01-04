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
#include <stdlib.h>
#include <string.h>
#include <junkie/proto/pkt_wait_list.h>
#include <junkie/tools/log.h>
#include <junkie/tools/mallocer.h>

static char const Id[] = "$Id$";

/*
 * Destruction of a pending packet
 */

/* There is no such thing as a destructor for proto_info, since they are constructed on the stack.
 * Also, notice that normaly the pointer to parser is not a counted ref since these proto_info are normaly
 * build on the stack, but for our copies on the heap we need a proper ref, so we unref them here. */
static void proto_info_del_rec(struct proto_info *info)
{
    void *start = (void *)info->parser->proto->ops->info_addr(info, NULL);

    info->parser = parser_unref(info->parser);

    if (info->parent) {
        proto_info_del_rec(info->parent);
        info->parent = NULL;
    }

    FREE(start);
}

static void pkt_wait_dtor(struct pkt_wait *pkt, struct pkt_wait_list *pkt_wl)
{
    assert(pkt_wl->nb_pkts > 0);
    assert(pkt_wl->tot_payload >= pkt->cap_len);
    LIST_REMOVE(pkt, entry);
    pkt_wl->nb_pkts --;
    pkt_wl->tot_payload -= pkt->cap_len;

    if (pkt->packet) {
        FREE(pkt->packet);
        pkt->packet = NULL;
    }
    if (pkt->parent) {
        proto_info_del_rec(pkt->parent);
        pkt->parent = NULL;
    }
}

void pkt_wait_del(struct pkt_wait *pkt, struct pkt_wait_list *pkt_wl)
{
    pkt_wait_dtor(pkt, pkt_wl);
    FREE(pkt);
}

static enum proto_parse_status pkt_wait_parse(struct pkt_wait *pkt, struct pkt_wait_list *pkt_wl, struct timeval const *now)
{
    if (
        ! pkt_wl->parser ||                         // if we have no parser,
        pkt_wl->next_offset >= pkt->next_offset ||  // or the pkt content was completely covered,
        pkt->offset > pkt_wl->next_offset           // or the pkt was supposed to come later,
    ) {
        // then do not parse it
        return proto_parse(NULL, pkt->parent, pkt->way, NULL, 0, 0, now, pkt->okfn);
    }

    // So we must parse from pkt_wl->next_offset to pkt->next_offset
    assert(pkt->offset <= pkt_wl->next_offset);
    unsigned trim = pkt_wl->next_offset - pkt->offset;
    enum proto_parse_status const status =
        trim < pkt->cap_len ?
            proto_parse(pkt_wl->parser, pkt->parent, pkt->way, pkt->packet + trim, pkt->cap_len - trim, pkt->packet_len - trim, now, pkt->okfn) :
            proto_parse(pkt_wl->parser, pkt->parent, pkt->way, NULL, 0, trim < pkt->packet_len ? pkt->packet_len - trim : 0, now, pkt->okfn);
    pkt_wl->next_offset = pkt->next_offset;
    return status;
}

static enum proto_parse_status pkt_wait_finalize(struct pkt_wait *pkt, struct pkt_wait_list *pkt_wl, struct timeval const *now)
{
    enum proto_parse_status status = pkt_wait_parse(pkt, pkt_wl, now);
    pkt_wait_del(pkt, pkt_wl);
    return status;
}

/*
 * Construction of a waiting packet
 */

static struct proto_info *copy_info_rec(struct proto_info *info)
{
    MALLOCER(waiting_infos);
    if (! info) return NULL;

    struct proto_info *parent = copy_info_rec(info->parent);

    size_t size;
    void *start = (void *)info->parser->proto->ops->info_addr(info, &size);
    void *copy = MALLOC(waiting_infos, size);
    if (! copy) {
        SLOG(LOG_WARNING, "Cannot alloc for pending info");
        if (parent) proto_info_del_rec(parent);
        return NULL;
    }
    memcpy(copy, start, size);

    struct proto_info *copy_info = (struct proto_info *)(((char *)copy) + ((char *)info - (char *)start));
    copy_info->parent = parent;
    copy_info->parser = parser_ref(info->parser);

    return copy_info;
}

// Construct it but does not insert it into the pkt_wait list
static int pkt_wait_ctor(struct pkt_wait *pkt, unsigned offset, unsigned next_offset, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t packet_len, proto_okfn_t *okfn)
{
    MALLOCER(waiting_payloads);

    pkt->offset = offset;
    pkt->next_offset = next_offset;
    pkt->cap_len = cap_len;
    pkt->packet_len = packet_len;
    pkt->way = way;
    pkt->okfn = okfn;
    pkt->packet = MALLOC(waiting_payloads, cap_len);
    if (! pkt->packet) {
        SLOG(LOG_WARNING, "Cannot alloc for pending payload");
        return -1;
    }
    memcpy(pkt->packet, packet, cap_len);

    if (parent) {
        pkt->parent = copy_info_rec(parent);
        if (! pkt->parent) {
            FREE(pkt->packet);
            pkt->packet = NULL;
            return -1;
        }
    } else {
        pkt->parent = NULL;
    }

    return 0;
}

static struct pkt_wait *pkt_wait_new(unsigned offset, unsigned next_offset, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t packet_len, proto_okfn_t *okfn)
{
    MALLOCER(waiting_pkts);
    struct pkt_wait *pkt = MALLOC(waiting_pkts, sizeof(*pkt));
    if (! pkt) {
        SLOG(LOG_WARNING, "Cannot malloc for waiting packet");
        return NULL;
    }

    if (0 != pkt_wait_ctor(pkt, offset, next_offset, parent, way, packet, cap_len, packet_len, okfn)) {
        FREE(pkt);
        return NULL;
    }

    return pkt;
}

/*
 * Waiting list management
 */

int pkt_wait_list_ctor(struct pkt_wait_list *pkt_wl, unsigned next_offset, unsigned timeout, unsigned acceptable_gap, unsigned nb_pkts_max, size_t payload_max, struct parser *parser)
{
    SLOG(LOG_DEBUG, "Construct pkt_wait_list @%p", pkt_wl);

    LIST_INIT(&pkt_wl->pkts);
    pkt_wl->nb_pkts = 0;
    pkt_wl->tot_payload = 0;
    pkt_wl->next_offset = next_offset;
    pkt_wl->acceptable_gap = acceptable_gap;
    pkt_wl->nb_pkts_max = nb_pkts_max;
    pkt_wl->payload_max = payload_max;
    timeval_reset(&pkt_wl->last_insert);
    pkt_wl->timeout = timeout;
    pkt_wl->parser = parser_ref(parser);

    return 0;
}

void pkt_wait_list_dtor(struct pkt_wait_list *pkt_wl, struct timeval const *now)
{
    // start by cleaning the parser so that the subparse method won't be called
    pkt_wl->parser = parser_unref(pkt_wl->parser);

    // then call the callbacks for each pending packet
    struct pkt_wait *pkt;
    while (NULL != (pkt = LIST_FIRST(&pkt_wl->pkts))) {
        (void)pkt_wait_finalize(pkt, pkt_wl, now);
    }
    assert(pkt_wl->nb_pkts == 0);
    assert(pkt_wl->tot_payload == 0);
}

static int offset_compare(unsigned o1, unsigned n1, unsigned o2, unsigned n2)
{
    // We want first the first offset. If both are equal, then we want first the packet that ends first
    if (o1 < o2) return -1;
    if (o1 > o2) return 1;
    if (n1 < n2) return -1;
    if (n1 > n2) return 1;
    return 0;
}

enum proto_parse_status pkt_wait_list_add(struct pkt_wait_list *pkt_wl, unsigned offset, unsigned next_offset, bool can_parse, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t packet_len, struct timeval const *now, proto_okfn_t *okfn)
{
    SLOG(LOG_DEBUG, "Add a packet of %zu bytes at offset %u to waiting list @%p", packet_len, offset, pkt_wl);

    // Find its location and the previous pkt
    struct pkt_wait *prev = NULL;
    struct pkt_wait *next;
    LIST_FOREACH(next, &pkt_wl->pkts, entry) {
        if (offset_compare(offset, next_offset, next->offset, next->next_offset) <= 0) {    // this packet come before next, insert here
            break;
        }
        prev = next;
    }

    // if previous == NULL and pkt_wl->next_offset == offset, call proto_parse directly, then advance next_offset.
    if (! prev && pkt_wl->next_offset == offset && can_parse) {
        enum proto_parse_status status = proto_parse(pkt_wl->parser, parent, way, packet, cap_len, packet_len, now, okfn);

        // Now parse as much as we can while advancing next_offset, returning the first error we obtain
        pkt_wl->next_offset = next_offset;
        while (status == PROTO_OK) {
            struct pkt_wait *pkt = LIST_FIRST(&pkt_wl->pkts);
            if (! pkt) break;
            if (pkt->offset > pkt_wl->next_offset) break;
            status = pkt_wait_finalize(pkt, pkt_wl, now);
        }
        return status;
    }

    // else if gap with previous > acceptable_gap or if the packet is fully in the past
    // then call okfn directly and we are done
    unsigned prev_offset = prev ? prev->offset : pkt_wl->next_offset;
    if (
        (pkt_wl->acceptable_gap > 0 && (int)(offset - prev_offset) > (int)pkt_wl->acceptable_gap) ||
        (int)(next_offset - prev_offset) <= 0
    ) {
        return proto_parse(NULL, parent, way, packet, cap_len, packet_len, now, okfn);
    }

    // else insert the packet and wait
    struct pkt_wait *pkt = pkt_wait_new(offset, next_offset, parent, way, packet, cap_len, packet_len, okfn);
    if (! pkt) return proto_parse(NULL, parent, way, NULL, 0, 0, now, okfn); // silently discard

    if (prev) {
        LIST_INSERT_AFTER(prev, pkt, entry);
    } else {
        LIST_INSERT_HEAD(&pkt_wl->pkts, pkt, entry);
    }
    pkt_wl->last_insert = *now;
    pkt_wl->nb_pkts ++;
    pkt_wl->tot_payload += pkt->cap_len;
    return PROTO_OK;
}

bool pkt_wait_list_is_complete(struct pkt_wait_list *pkt_wl, unsigned start_offset, unsigned end_offset)
{
    unsigned end = start_offset;
    struct pkt_wait *pkt;
    LIST_FOREACH(pkt, &pkt_wl->pkts, entry) {
        if (pkt->next_offset <= end) continue;
        if (pkt->offset > end) break;
        end = pkt->next_offset;
        if (end >= end_offset) return true;
    }

    return false;
}

uint8_t *pkt_wait_list_reassemble(struct pkt_wait_list *pkt_wl, unsigned start_offset, unsigned end_offset)
{
    MALLOCER(reassembled_payloads);
    assert(end_offset >= start_offset);

    SLOG(LOG_DEBUG, "Reassemble pkt_wl@%p from offset %u to %u", pkt_wl, start_offset, end_offset);

    uint8_t *payload = MALLOC(reassembled_payloads, end_offset - start_offset);
    if (! payload) {
        SLOG(LOG_DEBUG, "Cannot alloc for packet reassembly of %zu bytes", pkt_wl->tot_payload);
        return NULL;
    }

    unsigned end = start_offset;   // we filled payload up to there
    struct pkt_wait *pkt;
    LIST_FOREACH(pkt, &pkt_wl->pkts, entry) {
        if (pkt->next_offset <= end) continue;
        if (pkt->offset > end) break;
        unsigned const trim_left = pkt->offset - end;
        if (trim_left >= pkt->cap_len) break;
        unsigned next_end = pkt->offset + pkt->cap_len;
        if (next_end > end_offset) next_end = end_offset;
        SLOG(LOG_DEBUG, "  Copy from pkt@%p from offset %u (%u) %u bytes at location %u", pkt, trim_left, pkt->offset + trim_left, next_end - end, end-start_offset);
        assert(end-start_offset < end_offset-start_offset); // no buffer overrun
        assert(trim_left + (next_end-end) <= pkt->cap_len); // don't read out of pkt->packet
        memcpy(payload + (end-start_offset), pkt->packet + trim_left, next_end - end);
        end = next_end;
    }

    if (end != end_offset) {
        FREE(payload);
        return NULL;
    }

    return payload;
}

