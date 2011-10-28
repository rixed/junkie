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
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <inttypes.h>
#include "junkie/cpp.h"
#include "junkie/tools/log.h"
#include "junkie/tools/tempstr.h"
#include "junkie/tools/miscmacs.h"
#include "junkie/tools/ip_addr.h"
#include "junkie/tools/serialize.h"
#include "junkie/proto/proto.h"
#include "junkie/proto/ip.h"
#include "junkie/proto/arp.h"
#include "junkie/proto/eth.h"
#include "junkie/tools/ext.h"

static char const Id[] = "$Id: 70c2033b6d5c020b1a0f8c367cf57c2cfb996c84 $";

#undef LOG_CAT
#define LOG_CAT proto_eth_log_category

LOG_CATEGORY_DEF(proto_eth);

static bool collapse_vlans = true;
EXT_PARAM_RW(collapse_vlans, "collapse-vlans", bool, "Set to true if packets from distinct vlans share the same address range");
static const int vlan_unset = VLAN_UNSET;

// Description of an Ethernet header
struct eth_hdr {
	unsigned char dst[ETH_ADDR_LEN];
	unsigned char src[ETH_ADDR_LEN];
	uint16_t proto;
} packed_;

/*
 * Tools
 */

bool eth_addr_is_broadcast(unsigned char const addr[ETH_ADDR_LEN])
{
    static unsigned char all_ones[ETH_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    return 0 == memcmp(addr, all_ones, sizeof(all_ones));
}

/*
 * Proto Infos
 */

char const *eth_addr_2_str(unsigned char const addr[ETH_ADDR_LEN])
{
    char *str = tempstr();
    size_t len = 0;
    unsigned i;
    for (i = 0; i < ETH_ADDR_LEN; i ++) {
        len += snprintf(str+len, TEMPSTR_SIZE-len, "%s%.02x", len > 0 ? ":":"", addr[i]);
    }
    return str;
}

static void const *eth_info_addr(struct proto_info const *info_, size_t *size)
{
    struct eth_proto_info const *info = DOWNCAST(info_, info, eth_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *eth_info_2_str(struct proto_info const *info_)
{
    struct eth_proto_info const *info = DOWNCAST(info_, info, eth_proto_info);
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "%s, vlan_id=%d, source=%s, dest=%s, proto=%u",
        proto_info_2_str(info_),
        info->vlan_id,
        eth_addr_2_str(info->addr[0]),
        eth_addr_2_str(info->addr[1]),
        info->protocol);
    return str;
}

static void eth_serialize(struct proto_info const *info_, uint8_t **buf)
{
    struct eth_proto_info const *info = DOWNCAST(info_, info, eth_proto_info);
    proto_info_serialize(info_, buf);
    serialize_3(buf, info->vlan_id);    // 16 bits for vlan itself, +we need to handle -1 for UNSET
    serialize_n(buf, info->addr[0], ETH_ADDR_LEN);
    serialize_n(buf, info->addr[1], ETH_ADDR_LEN);
    serialize_2(buf, info->protocol);
}

static void eth_deserialize(struct proto_info *info_, uint8_t const **buf)
{
    struct eth_proto_info *info = DOWNCAST(info_, info, eth_proto_info);
    proto_info_deserialize(info_, buf);
    info->vlan_id = deserialize_3(buf);
    if (info->vlan_id == 0xffffff) info->vlan_id = -1;
    deserialize_n(buf, info->addr[0], ETH_ADDR_LEN);
    deserialize_n(buf, info->addr[1], ETH_ADDR_LEN);
    info->protocol = deserialize_2(buf);
}

static void eth_proto_info_ctor(struct eth_proto_info *info, struct parser *parser, struct proto_info *parent, size_t head_len, size_t payload, uint16_t proto, int vlan_id, struct eth_hdr const *ethhdr)
{
    proto_info_ctor(&info->info, parser, parent, head_len, payload);

    info->vlan_id = collapse_vlans ? vlan_unset : vlan_id;
    ASSERT_COMPILE(sizeof(info->addr[0]) == sizeof(ethhdr->src));
    memcpy(info->addr[0], ethhdr->src, sizeof(info->addr[0]));
    ASSERT_COMPILE(sizeof(info->addr[1]) == sizeof(ethhdr->dst));
    memcpy(info->addr[1], ethhdr->dst, sizeof(info->addr[1]));
    info->protocol = proto;
}

/*
 * Subproto management
 */

static LIST_HEAD(eth_subprotos, eth_subproto) eth_subprotos;
static struct mutex eth_subprotos_mutex;

void eth_subproto_ctor(struct eth_subproto *eth_subproto, unsigned protocol, struct proto *proto)
{
    SLOG(LOG_DEBUG, "Adding proto %s for protocol value %u", proto->name, protocol);
    eth_subproto->protocol = protocol;
    eth_subproto->proto = proto;
    mutex_lock(&eth_subprotos_mutex);
    LIST_INSERT_HEAD(&eth_subprotos, eth_subproto, entry);
    mutex_unlock(&eth_subprotos_mutex);
}

void eth_subproto_dtor(struct eth_subproto *eth_subproto)
{
    SLOG(LOG_DEBUG, "Removing proto %s for protocol value %u", eth_subproto->proto->name, eth_subproto->protocol);
    mutex_lock(&eth_subprotos_mutex);
    LIST_REMOVE(eth_subproto, entry);
    mutex_unlock(&eth_subprotos_mutex);
}

struct proto *eth_subproto_lookup(unsigned protocol)
{
    struct eth_subproto *subproto;
    LIST_LOOKUP_LOCKED(subproto, &eth_subprotos, entry, subproto->protocol == protocol, &eth_subprotos_mutex);

    return subproto ? subproto->proto : NULL;
}

/*
 * Parse
 */

struct mux_subparser *eth_subparser_and_parser_new(struct parser *parser, struct proto *proto, struct proto *requestor, int vlan_id, struct timeval const *now)
{
    struct mux_parser *mux_parser = DOWNCAST(parser, parser, mux_parser);
    return mux_subparser_and_parser_new(mux_parser, proto, requestor, collapse_vlans ? &vlan_unset : &vlan_id, now);
}

static enum proto_parse_status eth_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct mux_parser *mux_parser = DOWNCAST(parser, parser, mux_parser);
    struct eth_hdr const *ethhdr = (struct eth_hdr *)packet;
    uint16_t h_proto = READ_U16N(&ethhdr->proto);
    int vlan_id = VLAN_UNSET;
    size_t ethhdr_len = sizeof(*ethhdr);

    // Sanity checks
    if (wire_len < ethhdr_len) {
        SLOG(LOG_DEBUG, "Bogus Eth packet: too short (%zu < %zu)", wire_len, ethhdr_len);
        return PROTO_PARSE_ERR;
    }

    if (cap_len < ethhdr_len) return PROTO_TOO_SHORT;

    if (h_proto == 0) {  // Take into account Linux Cooked Capture
        if (cap_len < ethhdr_len + 2) return PROTO_TOO_SHORT;
        struct eth_lcc {
            uint16_t h_proto;
        } packed_ *eth_lcc = (struct eth_lcc *)((char *)ethhdr + ethhdr_len);
        h_proto = READ_U16N(&eth_lcc->h_proto);
        ethhdr_len += 2;
        // We dont care about the source MAC being funny
    }

    if (h_proto == ETH_PROTO_8021Q) {   // Take into account 802.1q vlan tag
        if (cap_len < ethhdr_len + 4) return PROTO_TOO_SHORT;
        struct eth_vlan {
            uint16_t vlan_id, h_proto;
        } packed_ *eth_vlan = (struct eth_vlan *)((char *)ethhdr + ethhdr_len);
        h_proto = READ_U16N(&eth_vlan->h_proto);
        vlan_id = READ_U16N(&eth_vlan->vlan_id) & 0xfff;
        ethhdr_len += 4;
    }

    size_t frame_wire_len = wire_len - ethhdr_len;

    if (h_proto <= 1500) {  // h_proto is then the length of payload
        /* According to IEEE Std.  802.3:
         * "This two-octet field takes one of two meanings, depending on its numeric value. For numerical evaluation,
         * the first octet is the most significant octet of this field.
         *    a) If the value of this field is less than or equal to 1500 decimal (05DC hexadecimal), then the Length/
         *       Type field indicates the number of MAC client data octets contained in the subsequent MAC Client
         *       Data field of the basic frame (Length interpretation).
         *    b) If the value of this field is greater than or equal to 1536 decimal (0600 hexadecimal), then the
         *       Length/Type field indicates the nature of the MAC client protocol (Type interpretation).
         *       The Length and Type interpretations of this field are mutually exclusive."
         */
        if (h_proto > frame_wire_len) {
            SLOG(LOG_DEBUG, "Bogus Eth packet: specified length too bug (%"PRIu16" > %zu)", h_proto, frame_wire_len);
            return PROTO_PARSE_ERR;
        }

        frame_wire_len = h_proto;
        h_proto = 0;    // no indication of a protocol, then
    }

    size_t const frame_cap_len = MIN(cap_len - ethhdr_len, frame_wire_len);
    // Parse
    struct eth_proto_info info;
    eth_proto_info_ctor(&info, parser, parent, ethhdr_len, frame_wire_len, h_proto, vlan_id, ethhdr);

    if (! h_proto) goto fallback;   // no indication of what's the payload

    struct proto *sub_proto = eth_subproto_lookup(h_proto);
    struct mux_subparser *subparser = mux_subparser_lookup(mux_parser, sub_proto, NULL, collapse_vlans ? &vlan_unset : &vlan_id, now);

    if (! subparser) goto fallback;

    assert(ethhdr_len <= cap_len);

    enum proto_parse_status status = proto_parse(subparser->parser, &info.info, way, packet + ethhdr_len, frame_cap_len, frame_wire_len, now, okfn, tot_cap_len, tot_packet);
    mux_subparser_unref(subparser);

    if (status == PROTO_OK) return PROTO_OK;

fallback:
    (void)proto_parse(NULL, &info.info, way, packet + ethhdr_len, frame_cap_len, frame_wire_len, now, okfn, tot_cap_len, tot_packet);
    return PROTO_OK;
}

/*
 * Construction/Destruction
 */

static struct mux_proto mux_proto_eth;
struct proto *proto_eth = &mux_proto_eth.proto;

void eth_init(void)
{
    log_category_proto_eth_init();
    ext_param_collapse_vlans_init();
    mutex_ctor(&eth_subprotos_mutex, "Eth subprotocols");

    static struct proto_ops const ops = {
        .parse       = eth_parse,
        .parser_new  = mux_parser_new,
        .parser_del  = mux_parser_del,
        .info_2_str  = eth_info_2_str,
        .info_addr   = eth_info_addr,
        .serialize   = eth_serialize,
        .deserialize = eth_deserialize,
    };
    mux_proto_ctor(&mux_proto_eth, &ops, &mux_proto_ops, "Ethernet", PROTO_CODE_ETH, sizeof(vlan_unset) /* vlan_id */, 11);
    LIST_INIT(&eth_subprotos);
}

void eth_fini(void)
{
    assert(LIST_EMPTY(&eth_subprotos));
    mux_proto_dtor(&mux_proto_eth);
    mutex_dtor(&eth_subprotos_mutex);
    ext_param_collapse_vlans_fini();
    log_category_proto_eth_fini();
}
