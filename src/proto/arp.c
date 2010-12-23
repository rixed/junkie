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
#include <stdbool.h>
#include <netinet/ether.h>  // for struct ether_arp
#include <junkie/cpp.h>
#include <junkie/tools/log.h>
#include <junkie/tools/ip_addr.h>
#include <junkie/proto/proto.h>
#include <junkie/proto/eth.h>   // for eth_addr_2_str()
#include <junkie/proto/arp.h>

static char const Id[] = "$Id: 41d9ce8a5da8afbfb5153b5c45632295bc52b6f9 $";

#undef LOG_CAT
#define LOG_CAT proto_arp_log_category

LOG_CATEGORY_DEC(proto_arp);
LOG_CATEGORY_DEF(proto_arp);

/*
 * Parse
 */

static char const *arp_opcode_2_str(uint16_t opcode)
{
    switch (opcode) {
        case 1: return "request";
        case 2: return "response";
    }
    return "unknown";
}

static char const *arp_info_2_str(struct proto_info const *info_)
{
    struct arp_proto_info const *info = DOWNCAST(info_, info, arp_proto_info);
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "%s, opcode=%s, sender=%s, target=%s, target MAC=%s",
        proto_info_2_str(info_),
        arp_opcode_2_str(info->opcode),
        info->proto_addr_is_ip ? ip_addr_2_str(&info->sender) : "unset",
        info->proto_addr_is_ip ? ip_addr_2_str(&info->target) : "unset",
        info->hw_addr_is_eth ? eth_addr_2_str(info->hw_target) : "unset");

    return str;
}

static void fetch_ip(struct ip_addr *ip, uint16_t ar_pro, uint8_t const *ptr)
{
    switch (ar_pro) {
        case ETH_P_IP:;
            uint32_t addr;
            memcpy(&addr, ptr, sizeof(addr));
            ip_addr_ctor_from_ip4(ip, addr);
            break;
        case ETH_P_IPV6:
            ip_addr_ctor_from_ip6(ip, (struct in6_addr *)ptr);
            break;
    }
}

static void fetch_hw(uint8_t mac[ETH_ALEN], uint16_t ar_hrd, uint8_t const *ptr)
{
    if (ar_hrd == 1) {
        memcpy(mac, ptr, 16);
    } else {
        memset(mac, 0, 16);
    }
}

static enum proto_parse_status arp_parse(struct parser *parser, struct proto_layer *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn)
{
    struct ether_arp const *arp = (struct ether_arp *)payload;

    // Sanity Checks

    // Check that we have at least the size of an ARP packet for IP protocol
    if (wire_len < sizeof(*arp)) return PROTO_PARSE_ERR;
    // And that we have enough data to parse it
    if (cap_len < sizeof(*arp)) return PROTO_TOO_SHORT;

    // Now that we can dereference enough of the payload, display a useful log message
    SLOG(LOG_DEBUG, "New ARP packet with hard addr type %hu and proto addr type %hu", arp->ea_hdr.ar_hrd, arp->ea_hdr.ar_pro);
    
    unsigned const ar_hrd = ntohs(arp->ea_hdr.ar_hrd);
    unsigned const ar_pro = ntohs(arp->ea_hdr.ar_pro);
    size_t const ar_hln = arp->ea_hdr.ar_hln;
    size_t const ar_pln = arp->ea_hdr.ar_pln;

    size_t arp_msg_size = sizeof(arp->ea_hdr) + 2*ar_hln + 2*ar_pln;
    if (wire_len < arp_msg_size) return PROTO_PARSE_ERR;
    if (cap_len < arp_msg_size) return PROTO_TOO_SHORT;

    // Check addr length correspond to advertised types
    if (ar_hrd == 1 /* Ethernet */ && ar_hln != 6) {
        SLOG(LOG_DEBUG, "Bad hard addr length for Ethernet (%zu)", ar_hln);
        return PROTO_PARSE_ERR;
    }
    if (ar_pro == ETH_P_IP && ar_pln != 4) {
        SLOG(LOG_DEBUG, "Bad hard addr length for IPv4 (%zu)", ar_pln);
        return PROTO_PARSE_ERR;
    }
    if (ar_pro == ETH_P_IPV6 && ar_pln != 16) {
        SLOG(LOG_DEBUG, "Bad hard addr length for IPv6 (%zu)", ar_pln);
        return PROTO_PARSE_ERR;
    }

    // Check operation code
    uint16_t const opcode = ntohs(arp->ea_hdr.ar_op);
    if (opcode != ARPOP_REQUEST && opcode != ARPOP_REPLY) {
        SLOG(LOG_DEBUG, "Unknown ARP opcode (%hu)", opcode);
        return PROTO_PARSE_ERR;
    }

    // Now build the proto_layer and proto_info
    struct arp_proto_info info;
    static struct proto_info_ops ops = {
        .to_str = arp_info_2_str,
    };
    proto_info_ctor(&info.info, &ops, arp_msg_size, wire_len - arp_msg_size);

    // Gather all interesting data
    info.opcode = opcode;
    info.proto_addr_is_ip = ar_pro == ETH_P_IP || ar_pro == ETH_P_IPV6;
    info.hw_addr_is_eth = ar_hrd == 1;

    uint8_t const *ptr = (uint8_t *)arp->arp_sha;
    ptr += arp->ea_hdr.ar_hln;  // skip sender's hw addr

    fetch_ip(&info.sender, ar_pro, ptr);
    ptr += ar_pln;
    
    fetch_hw(info.hw_target, ar_hrd, ptr);
    ptr += ar_hln;

    fetch_ip(&info.target, ar_pro, ptr);
    ptr += ar_pln;

    struct proto_layer layer;
    proto_layer_ctor(&layer, parent, parser, &info.info);

    // And we are done
    return proto_parse(NULL, &layer, way, NULL, 0, 0, now, okfn);
}

/*
 * Construction/Destruction
 */

static struct uniq_proto uniq_proto_arp;
struct proto *proto_arp = &uniq_proto_arp.proto;
static struct eth_subproto arp_eth_subproto;

void arp_init(void)
{
    log_category_proto_arp_init();

    static struct proto_ops const ops = {
        .parse = arp_parse,
        .parser_new = uniq_parser_new,
        .parser_del = uniq_parser_del,
    };
    uniq_proto_ctor(&uniq_proto_arp, &ops, "ARP");
    eth_subproto_ctor(&arp_eth_subproto, ETH_P_ARP, proto_arp);
}

void arp_fini(void)
{
    eth_subproto_dtor(&arp_eth_subproto);
    uniq_proto_dtor(&uniq_proto_arp);
    log_category_proto_arp_fini();
}
