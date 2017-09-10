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
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include "junkie/cpp.h"
#include "junkie/tools/log.h"
#include "junkie/tools/miscmacs.h"
#include "junkie/tools/tempstr.h"
#include "junkie/tools/objalloc.h"
#include "junkie/tools/ext.h"
#include "junkie/proto/proto.h"
#include "junkie/proto/eth.h"
#include "junkie/proto/ip.h"
#include "junkie/proto/pkt_wait_list.h"
#include "proto/ip_hdr.h"

#undef LOG_CAT
#define LOG_CAT proto_ip_log_category

LOG_CATEGORY_DEF(proto_ip);

#define IP_HASH_SIZE 30011 /* with a max collision rate of 16 we can store 30k*16*2=approx 1M simultaneous IP addr pairs */

static bool reassembly_enabled = true;
EXT_PARAM_RW(reassembly_enabled, "ip-reassembly", bool, "Whether IP fragments reassembly is enabled or not.")

/*
 * Tools
 */

static bool is_fragment(struct ip_hdr const *ip)
{
    // No need to set fragment offset in host byte order to test for 0
    return
        unlikely_(READ_U8(&ip->frag_offset_lo)) ||
        unlikely_(READ_U8(&ip->flags) & IP_FRAG_OFFSET_MASK) ||
        unlikely_(READ_U8(&ip->flags) & IP_MORE_FRAGS_MASK);
}

static unsigned fragment_offset(struct ip_hdr const *ip)
{
    return (READ_U8(&ip->frag_offset_lo) + (READ_U8(&ip->flags) & IP_FRAG_OFFSET_MASK) * 256) * 8;
}

/*
 * Proto Infos
 */

void const *ip_info_addr(struct proto_info const *info_, size_t *size)
{
    struct ip_proto_info const *info = DOWNCAST(info_, info, ip_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

char const *ip_proto_2_str(unsigned protocol)
{
    switch (protocol) {
        case 1: return "ICMP";
        case 2: return "IGMP";
        case 3: return "GGP";
        case 4: return "IP-ENCAP";
        case 5: return "ST";
        case 6: return "TCP";
        case 8: return "EGP";
        case 9: return "IGP";
        case 12: return "PUP";
        case 17: return "UDP";
        case 20: return "HMP";
        case 22: return "XNS-IDP";
        case 27: return "RDP";
        case 29: return "ISO-TP4";
        case 33: return "DCCP";
        case 36: return "XTP";
        case 37: return "DDP";
        case 38: return "IDPR-CMTP";
        case 41: return "IPv6";
        case 43: return "IPv6-Route";
        case 44: return "IPv6-Frag";
        case 45: return "IDRP";
        case 46: return "RSVP";
        case 47: return "GRE";
        case 50: return "IPSEC-ESP";
        case 51: return "IPSEC-AH";
        case 57: return "SKIP";
        case 58: return "IPv6-ICMP";
        case 59: return "IPv6-NoNxt";
        case 60: return "IPv6-Opts";
        case 73: return "RSPF";
        case 81: return "VMTP";
        case 88: return "EIGRP";
        case 89: return "OSPFIGP";
        case 93: return "AX.25";
        case 94: return "IPIP";
        case 97: return "ETHERIP";
        case 98: return "ENCAP";
        case 103: return "PIM";
        case 108: return "IPCOMP";
        case 112: return "VRRP";
        case 115: return "L2TP";
        case 124: return "ISIS";
        case 132: return "SCTP";
        case 133: return "FC";
        case 136: return "UDPLite";
        case 137: return "MPLS-in-IP";
        case 138: return "MANET";
        case 139: return "HIP";
        case 140: return "Shim6";
        case 141: return "WESP";
        case 142: return "ROHC";
    }

    return tempstr_printf("%u", protocol);
}

char const *ip_fragmentation_2_str(enum ip_fragmentation frag)
{
    switch (frag) {
        case IP_NOFRAG:      return "NoFrag";
        case IP_DONTFRAG:    return "DontFrag";
        case IP_FRAGMENT:    return "Fragment";
        case IP_REASSEMBLED: return "Reassembled";
    }

    assert(!"INVALID fragmentation status");
}

static char const *ecn_2_str(unsigned ecn)
{
    switch (ecn) {
        case 0: return "NonECT";
        case 1: return "ECT(0)";
        case 2: return "ECT(2)";
        case 3: return "CE";
    }
    assert(!"Invalid ECN");
}

static char const *traffic_class_2_str(uint8_t traffic_class)
{
    return tempstr_printf("%u:%s", (traffic_class & IP_DSCP_MASK) >> 2, ecn_2_str(traffic_class & IP_TOS_ECN_MASK));
}

char const *ip_info_2_str(struct proto_info const *info_)
{
    struct ip_proto_info const *info = DOWNCAST(info_, info, ip_proto_info);
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "%s, version=%u, addr=%s->%s%s, proto=%s, ttl=%u, frag=%s, id=0x%04x, Class=%s",
        proto_info_2_str(info_),
        info->version,
        ip_addr_2_str(info->key.addr+0),
        ip_addr_2_str(info->key.addr+1),
        info->way ? " (hashed the other way)":"",
        ip_proto_2_str(info->key.protocol),
        info->ttl,
        info->version == 4 ? ip_fragmentation_2_str(info->fragmentation) : "na",
        info->version == 4 ? info->id : 0,
        traffic_class_2_str(info->traffic_class));
    return str;
}

static void ip_proto_info_ctor(struct ip_proto_info *info, struct parser *parser, struct proto_info *parent, size_t head_len, size_t payload, struct ip_hdr const *iphdr)
{
    proto_info_ctor(&info->info, parser, parent, head_len, payload);

    info->version = READ_U8(&iphdr->version_hdrlen) >> 4;
    ip_addr_ctor_from_ip4(&info->key.addr[0], READ_U32(&iphdr->src));
    ip_addr_ctor_from_ip4(&info->key.addr[1], READ_U32(&iphdr->dst));
    info->key.protocol = READ_U8(&iphdr->protocol);
    info->ttl = READ_U8(&iphdr->ttl);
    info->way = 0;  // will be set later
    if (is_fragment(iphdr)) {
        info->fragmentation = IP_FRAGMENT;  // may be changed later after optional reassembly
    } else {
        bool dont_frag = READ_U8(&iphdr->flags) & IP_DONT_FRAG_MASK;
        info->fragmentation = dont_frag ? IP_DONTFRAG : IP_NOFRAG;
    }
    info->id = READ_U16N(&iphdr->id);
    info->traffic_class = READ_U8(&iphdr->tos);
}

/*
 * Subproto management
 */

static LIST_HEAD(ip_subprotos, ip_subproto) ip_subprotos;
static struct mutex ip_subprotos_mutex;

void ip_subproto_ctor(struct ip_subproto *ip_subproto, unsigned protocol, struct proto *proto)
{
    SLOG(LOG_DEBUG, "Adding proto %s for protocol value %u", proto->name, protocol);
    ip_subproto->protocol = protocol;
    ip_subproto->proto = proto;
    mutex_lock(&ip_subprotos_mutex);
    LIST_INSERT_HEAD(&ip_subprotos, ip_subproto, entry);
    mutex_unlock(&ip_subprotos_mutex);
}

void ip_subproto_dtor(struct ip_subproto *ip_subproto)
{
    SLOG(LOG_DEBUG, "Removing proto %s for protocol value %u", ip_subproto->proto->name, ip_subproto->protocol);
    mutex_lock(&ip_subprotos_mutex);
    LIST_REMOVE(ip_subproto, entry);
    mutex_unlock(&ip_subprotos_mutex);
}

/*
 * Parse
 */

static struct mutex_pool ip_locks;

// We overload the mux_subparser to fit the pkt_wait_list required for IP reassembly
struct ip_subparser {
    /* We may have a list per IP id, but we do not want to create a pkt_list whenever a new id is encountered.
     * So we only creates a list if either the MoreFrag flag is set or the offset is > 0 (ie for first to last fragments).
     * Also, we check in the list iff this condition holds.
     * Each IP subparser can have at most 4 packets reassembled simultaneously, which should be more than
     * enought in all 'normal' situations. */
    /* Also, as an additional rule, we must not send fragments to the subparser before the packet is fully
     * reassembled, otherwise the subparser could receive the first fragment of id X then the first fragment
     * of id Y, which make no sense. */
    struct ip_reassembly {
        uint16_t in_use:1;
        uint16_t constructed:1;     // always 1 when in_use
        uint16_t got_last:1;        // set when we received the fragment without more_fragments flag
        uint16_t id;                // only valid when in_use flag is set
        unsigned end_offset;        // only valid when got_last flag is set
        struct pkt_wait_list wl;    // only constructed when constructed flag is set
    } reassembly[4];
    struct mutex *mutex;            // To protect the reassembly machinery
    struct mux_subparser mux_subparser;
};

static int ip_subparser_ctor(struct ip_subparser *ip_subparser, struct mux_parser *mux_parser, struct parser *child, struct proto *requestor, void const *key, struct timeval const *now)
{
    SLOG(LOG_DEBUG, "Construct an IP mux_subparser @%p", ip_subparser);
    CHECK_LAST_FIELD(ip_subparser, mux_subparser, struct mux_subparser);

    for (unsigned r = 0; r < NB_ELEMS(ip_subparser->reassembly); r++) {
        ip_subparser->reassembly[r].in_use = 0;
        ip_subparser->reassembly[r].constructed = 0;
        ip_subparser->reassembly[r].got_last = 0;
    }

    ip_subparser->mutex = mutex_pool_anyone(&ip_locks);

    // Now that everything is ready, make this subparser public
    if (0 != mux_subparser_ctor(&ip_subparser->mux_subparser, mux_parser, child, requestor, key, now)) {
        return -1;
    }

    return 0;
}

static struct mux_subparser *ip_subparser_new(struct mux_parser *mux_parser, struct parser *child, struct proto *requestor, void const *key, struct timeval const *now)
{
    struct ip_subparser *ip_subparser = mux_subparser_alloc(mux_parser, sizeof(*ip_subparser));
    if (! ip_subparser) return NULL;

    if (0 != ip_subparser_ctor(ip_subparser, mux_parser, child, requestor, key, now)) {
        objfree(ip_subparser);
        return NULL;
    }

    return &ip_subparser->mux_subparser;
}

static void ip_reassembly_dtor(struct ip_reassembly *reassembly)
{
    SLOG(LOG_DEBUG, "Destructing ip_reassembly@%p", reassembly);
    if (reassembly->constructed) {
        pkt_wait_list_dtor(&reassembly->wl);
        reassembly->constructed = 0;
        reassembly->in_use = 0;
    }
}

static void ip_subparser_dtor(struct ip_subparser *ip_subparser)
{
    SLOG(LOG_DEBUG, "Destruct an IP mux_subparser @%p", ip_subparser);

    for (unsigned r = 0; r < NB_ELEMS(ip_subparser->reassembly); r++) {
        ip_reassembly_dtor(ip_subparser->reassembly+r);
    }
    mux_subparser_dtor(&ip_subparser->mux_subparser);
}

static void ip_subparser_del(struct mux_subparser *mux_subparser)
{
    struct ip_subparser *ip_subparser = DOWNCAST(mux_subparser, mux_subparser, ip_subparser);
    ip_subparser_dtor(ip_subparser);
    objfree(ip_subparser);
}

static struct pkt_wl_config ip_reassembly_config;

// Really construct the waiting list
static int ip_reassembly_ctor(struct ip_reassembly *reassembly, struct parser *parser, uint16_t id)
{
    SLOG(LOG_DEBUG, "Constructing ip_reassembly@%p for parser %s", reassembly, parser_name(parser));
    assert(! reassembly->constructed);

    if (0 != pkt_wait_list_ctor(&reassembly->wl, 0, &ip_reassembly_config, parser, NULL)) return -1;
    reassembly->id = id;
    reassembly->got_last = 0;
    reassembly->constructed = 1;
    reassembly->in_use = 1;

    return 0;
}

static struct ip_reassembly *ip_reassembly_lookup(struct ip_subparser *ip_subparser, uint16_t id, struct parser *parser)
{
    SLOG(LOG_DEBUG, "Looking for ip_reassembly for id=%"PRIu16" for subparser %s", id, parser_name(parser));

    int last_unused = -1;
    for (unsigned r = 0; r < NB_ELEMS(ip_subparser->reassembly); r++) {
        struct ip_reassembly *const reassembly = ip_subparser->reassembly + r;
        if (reassembly->in_use) {
            if (reassembly->id != id) continue;
            SLOG(LOG_DEBUG, "Found id at index %u in ip_reassembly@%p", r, reassembly);
            if (! reassembly->constructed) {
                if (0 != ip_reassembly_ctor(reassembly, parser, id)) return NULL;
            }
            return reassembly;
        } else {
            last_unused = r;
        }
    }

    if (last_unused == -1) {
        last_unused = 0;    // a "random" value would be better
        SLOG(LOG_DEBUG, "No slot left on ip_reassembly, reusing slot at index %u", last_unused);
        ip_reassembly_dtor(ip_subparser->reassembly + last_unused);
    }

    struct ip_reassembly *const reassembly = ip_subparser->reassembly + last_unused;
    assert(! reassembly->in_use);
    if (0 != ip_reassembly_ctor(reassembly, parser, id)) return NULL;
    return reassembly;
}

unsigned ip_key_ctor(struct ip_key *k, unsigned protocol, struct ip_addr const *src, struct ip_addr const *dst)
{
    memset(k, 0, sizeof(*k));   // this struct uses some system wide structs that are not packed
    k->protocol = protocol;
    if (ip_addr_cmp(src, dst) <= 0) {
        k->addr[0] = *src;
        k->addr[1] = *dst;
        return 0;
    }
    k->addr[0] = *dst;
    k->addr[1] = *src;
    return 1;
}

struct mux_subparser *ip_subparser_lookup(struct parser *parser, struct proto *proto, struct proto *requestor, unsigned protocol, struct ip_addr const *src, struct ip_addr const *dst, unsigned *way, struct timeval const *now)
{
    struct mux_parser *mux_parser = DOWNCAST(parser, parser, mux_parser);
    struct ip_key key;
    *way = ip_key_ctor(&key, protocol, src, dst);
    return mux_subparser_lookup(mux_parser, proto, requestor, &key, now);
}

/* The pkt_wait_list is now complete.
 * Construct a single payload from it, then call the subparse once for this payload.
 * But we also want to acknoledge the several IP fragments that were received (but the
 * first one that count for the whole payload), so we also must call subscribers for
 * each IP info. The pkt_wait_list_dtor will do this for us. */
static enum proto_parse_status reassemble(struct ip_reassembly *reassembly)
{
    SLOG(LOG_DEBUG, "Reassembling ip_reassembly@%p", reassembly);

    /* FIXME: reassembled packet does not lie inside tot_packet, which is a problem if we use another pkt_wait_list in the subparser.
     * we should use wait_pkt->tot_packet here, or rework pkt_wait_list so that it doesn't assume anymore that packet is within tot_packet. */
    // may fail for instance if cap_len was not big enough
    uint8_t *payload = pkt_wait_list_reassemble(&reassembly->wl, 0, reassembly->end_offset);
    enum proto_parse_status status = pkt_wait_list_flush(&reassembly->wl, payload, reassembly->end_offset, reassembly->end_offset);
    if (payload) objfree(payload);
    ip_reassembly_dtor(reassembly);
    return status;
}

enum proto_parse_status ip_parse(struct parser *parser, struct proto_info *parent, unsigned unused_ way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct mux_parser *mux_parser = DOWNCAST(parser, parser, mux_parser);
    struct ip_hdr const *iphdr = (struct ip_hdr *)packet;

    // Sanity checks

    if (cap_len < sizeof(*iphdr)) return PROTO_TOO_SHORT;

    unsigned const protocol = READ_U8(&iphdr->protocol);
    unsigned const version = IP_VERSION(iphdr);
    size_t const iphdr_len = IP_HDR_LENGTH(iphdr);

    SLOG(LOG_DEBUG, "New packet of %zu bytes, proto %u, %"PRINIPQUAD"->%"PRINIPQUAD,
        wire_len, protocol, NIPQUAD(&iphdr->src), NIPQUAD(&iphdr->dst));

    size_t ip_len = READ_U16N(&iphdr->tot_len);
    if (ip_len > wire_len) {
        SLOG(LOG_DEBUG, "Bogus IPv4 total length: %zu > %zu", ip_len, wire_len);
        return PROTO_PARSE_ERR;
    }

    if (version != 4) {
        SLOG(LOG_DEBUG, "Bogus IPv4 version: %u instead of 4", version);
        return PROTO_PARSE_ERR;
    }

    if (iphdr_len > ip_len) {
        SLOG(LOG_DEBUG, "Bogus IPv4 header length: %zu > %zu", iphdr_len, ip_len);
        return PROTO_PARSE_ERR;
    }

    if (iphdr_len > cap_len) return PROTO_TOO_SHORT;

    // Parse

    struct ip_proto_info info;
    // Take care that wire/cap_len can be greater than ip payload (padding)
    size_t const payload = ip_len - iphdr_len;
    size_t const cap_payload = MIN(cap_len - iphdr_len, payload);
    ip_proto_info_ctor(&info, parser, parent, iphdr_len, payload, iphdr);

    // Find subparser

    struct mux_subparser *subparser = NULL;
    struct ip_subproto *subproto;
    LIST_LOOKUP_LOCKED(subproto, &ip_subprotos, entry, subproto->protocol == info.key.protocol, &ip_subprotos_mutex);
    if (subproto) {
        // We have a subproto for this protocol value, look for a parser of this subproto in our mux_subparsers hash (or create a new one)
        struct ip_key subparser_key;
        info.way = ip_key_ctor(&subparser_key, info.key.protocol, info.key.addr+0, info.key.addr+1);
        subparser = mux_subparser_lookup(mux_parser, subproto->proto, NULL, &subparser_key, now);
    }

    if (! subparser) {
        SLOG(LOG_DEBUG, "IPv4 protocol %u unknown", protocol);
        goto fallback;
    }

    enum proto_parse_status status;

    // If we have a fragment, maybe we can't parse payload right now
    if (is_fragment(iphdr) && reassembly_enabled) {
        struct ip_subparser *ip_subparser = DOWNCAST(subparser, mux_subparser, ip_subparser);
        // Do not tolerate concurrent access from this point
        mutex_lock(ip_subparser->mutex);
        unsigned const offset = fragment_offset(iphdr);
        uint16_t id = READ_U16N(&iphdr->id);
        SLOG(LOG_DEBUG, "IP packet is a fragment of id %"PRIu16", offset=%u", id, offset);
        struct ip_reassembly *reassembly = ip_reassembly_lookup(ip_subparser, id, subparser->parser);
        if (! reassembly) goto unlock_fallback;
        assert(reassembly->in_use && reassembly->constructed);
        if (! (READ_U8(&iphdr->flags) & IP_MORE_FRAGS_MASK)) {
            reassembly->got_last = 1;
            reassembly->end_offset = offset + payload;
            info.fragmentation = IP_REASSEMBLED;    // fix the info before it's copied by pkt_wait_list_add
        }
        if (PROTO_OK != pkt_wait_list_add(&reassembly->wl, offset, offset + payload, false, 0, false, &info.info, info.way, packet + iphdr_len, cap_payload, payload, now, tot_cap_len, tot_packet)) {
            goto unlock_fallback;  // should not happen
        }
        if (reassembly->got_last && pkt_wait_list_is_complete(&reassembly->wl, 0, reassembly->end_offset)) {
            status = reassemble(reassembly);
        } else {
            status = PROTO_OK;  // for now
        }
        mutex_unlock(ip_subparser->mutex);
        mux_subparser_unref(&subparser);
        return status;
unlock_fallback:    // Beeeerk
        mutex_unlock(ip_subparser->mutex);
        mux_subparser_unref(&subparser);
        goto fallback;
    }

    // Parse it at once
    status = proto_parse(subparser->parser, &info.info, info.way, packet + iphdr_len, cap_payload, payload, now, tot_cap_len, tot_packet);
    mux_subparser_unref(&subparser);
    if (status == PROTO_OK) return PROTO_OK;

fallback:
    (void)proto_parse(NULL, &info.info, info.way, packet + iphdr_len, cap_payload, payload, now, tot_cap_len, tot_packet);
    return PROTO_OK;
}

/*
 * Construction/Destruction
 */

struct mux_proto mux_proto_ip;
struct proto *proto_ip = &mux_proto_ip.proto;
static struct eth_subproto ip_eth_subproto;

void ip_init(void)
{
    mutex_pool_ctor(&ip_locks, "IP subparsers");
    log_category_proto_ip_init();
    ext_param_reassembly_enabled_init();
    mutex_ctor(&ip_subprotos_mutex, "IPv4 subprotocols");
    LIST_INIT(&ip_subprotos);
    pkt_wl_config_ctor(&ip_reassembly_config, "IP-reassembly", 65536, 100, 65536, 5 /* FRAGMENTATION TIMEOUT (second) */, false);

    static struct proto_ops const ops = {
        .parse       = ip_parse,
        .parser_new  = mux_parser_new,
        .parser_del  = mux_parser_del,
        .info_2_str  = ip_info_2_str,
        .info_addr   = ip_info_addr
    };
    static struct mux_proto_ops const mux_ops = {
        .subparser_new = ip_subparser_new,
        .subparser_del = ip_subparser_del,
    };
    mux_proto_ctor(&mux_proto_ip, &ops, &mux_ops, "IPv4", PROTO_CODE_IP, sizeof(struct ip_key), IP_HASH_SIZE);
    eth_subproto_ctor(&ip_eth_subproto, ETH_PROTO_IPv4, proto_ip);
}

void ip_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    assert(LIST_EMPTY(&ip_subprotos));
    eth_subproto_dtor(&ip_eth_subproto);
    mux_proto_dtor(&mux_proto_ip);
    pkt_wl_config_dtor(&ip_reassembly_config);
    mutex_dtor(&ip_subprotos_mutex);
    mutex_pool_dtor(&ip_locks);
#   endif
    ext_param_reassembly_enabled_fini();

    log_category_proto_ip_fini();
}
