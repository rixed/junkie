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
#include "junkie/cpp.h"
#include "junkie/tools/log.h"
#include "junkie/tools/ip_addr.h"
#include "junkie/proto/proto.h"
#include "junkie/proto/eth.h"   // for eth_addr_2_str()
#include "junkie/proto/arp.h"

#undef LOG_CAT
#define LOG_CAT proto_arp_log_category

LOG_CATEGORY_DEF(proto_arp);

// Description of an ARP header
struct arp_hdr {
    uint16_t hard_addr_fmt, prot_addr_fmt;
    uint8_t hard_addr_len, prot_addr_len;
    uint16_t opcode;
} packed_;

/*
 * Parse
 */

static char const *arp_opcode_2_str(enum arp_opcode opcode)
{
    switch (opcode) {
        case ARP_REQUEST: return "request";
        case ARP_REPLY:   return "reply";
    }
    assert(!"Unknown ARP opcode");
    return "unknown";
}

static void const *arp_info_addr(struct proto_info const *info_, size_t *size)
{
    struct arp_proto_info const *info = DOWNCAST(info_, info, arp_proto_info);
    if (size) *size = sizeof(*info);
    return info;
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

static void fetch_ip(struct ip_addr *ip, unsigned prot_addr_fmt, uint8_t const *ptr)
{
    switch (prot_addr_fmt) {
        case ETH_PROTO_IPv4:;
            uint32_t addr;
            memcpy(&addr, ptr, sizeof(addr));
            ip_addr_ctor_from_ip4(ip, addr);
            break;
        case ETH_PROTO_IPv6:
            ip_addr_ctor_from_ip6(ip, *(struct in6_addr *)ptr);
            break;
    }
}

static void fetch_hw(unsigned char *mac, unsigned hard_addr_fmt, uint8_t const *ptr)
{
    if (hard_addr_fmt == 1) {
        memcpy(mac, ptr, ETH_ADDR_LEN);
    } else {
        memset(mac, 0, ETH_ADDR_LEN);
    }
}

enum proto_parse_status arp_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct arp_hdr const *arp = (struct arp_hdr *)payload;

    // Sanity Checks

    // Check that we have at least the size of an ARP packet for IP protocol
    if (wire_len < sizeof(*arp)) return PROTO_PARSE_ERR;
    // And that we have enough data to parse it
    if (cap_len < sizeof(*arp)) return PROTO_TOO_SHORT;

    // Now that we can dereference enough of the payload, display a useful log message
    unsigned const hard_addr_fmt = READ_U16N(&arp->hard_addr_fmt);
    unsigned const prot_addr_fmt = READ_U16N(&arp->prot_addr_fmt);
    size_t const hard_addr_len = READ_U8(&arp->hard_addr_len);
    size_t const prot_addr_len = READ_U8(&arp->prot_addr_len);

    SLOG(LOG_DEBUG, "New ARP packet with hard addr type %u and proto addr type %u", hard_addr_fmt, prot_addr_fmt);

    size_t arp_msg_size = sizeof(*arp) + 2*hard_addr_len + 2*prot_addr_len;
    if (wire_len < arp_msg_size) return PROTO_PARSE_ERR;
    if (cap_len < arp_msg_size) return PROTO_TOO_SHORT;

    // Check addr length correspond to advertised types
    if (hard_addr_fmt == 1 /* Ethernet */ && hard_addr_len != ETH_ADDR_LEN) {
        SLOG(LOG_DEBUG, "Bad hard addr length for Ethernet (%zu)", hard_addr_len);
        return PROTO_PARSE_ERR;
    }
    if (prot_addr_fmt == ETH_PROTO_IPv4 && prot_addr_len != 4) {
        SLOG(LOG_DEBUG, "Bad hard addr length for IPv4 (%zu)", prot_addr_len);
        return PROTO_PARSE_ERR;
    }
    if (prot_addr_fmt == ETH_PROTO_IPv6 && prot_addr_len != 16) {
        SLOG(LOG_DEBUG, "Bad hard addr length for IPv6 (%zu)", prot_addr_len);
        return PROTO_PARSE_ERR;
    }

    // Check operation code
    unsigned const opcode = READ_U16N(&arp->opcode);
    if (opcode != ARP_REQUEST && opcode != ARP_REPLY) {
        SLOG(LOG_DEBUG, "Unknown ARP opcode (%u)", opcode);
        return PROTO_PARSE_ERR;
    }

    // Now build the proto_info
    struct arp_proto_info info;
    proto_info_ctor(&info.info, parser, parent, arp_msg_size, wire_len - arp_msg_size);

    // Gather all interesting data
    info.opcode = opcode;
    info.proto_addr_is_ip = prot_addr_fmt == ETH_PROTO_IPv4 || prot_addr_fmt == ETH_PROTO_IPv6;
    info.hw_addr_is_eth = hard_addr_fmt == 1;

    uint8_t const *ptr = (uint8_t *)arp + sizeof(*arp);
    ptr += hard_addr_len;  // skip sender's hw addr

    fetch_ip(&info.sender, prot_addr_fmt, ptr);
    ptr += prot_addr_len;

    fetch_hw(info.hw_target, hard_addr_fmt, ptr);
    ptr += hard_addr_len;

    fetch_ip(&info.target, prot_addr_fmt, ptr);
    ptr += prot_addr_len;

    // And we are done
    return proto_parse(NULL, &info.info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
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
        .parse       = arp_parse,
        .parser_new  = uniq_parser_new,
        .parser_del  = uniq_parser_del,
        .info_2_str  = arp_info_2_str,
        .info_addr   = arp_info_addr
    };
    uniq_proto_ctor(&uniq_proto_arp, &ops, "ARP", PROTO_CODE_ARP);
    eth_subproto_ctor(&arp_eth_subproto, ETH_PROTO_ARP, proto_arp);
}

void arp_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    eth_subproto_dtor(&arp_eth_subproto);
    uniq_proto_dtor(&uniq_proto_arp);
#   endif
    log_category_proto_arp_fini();
}
