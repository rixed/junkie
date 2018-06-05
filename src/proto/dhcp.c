// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2018, SecurActive.
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
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include "junkie/cpp.h"
#include "junkie/tools/log.h"
#include "junkie/proto/cursor.h"
#include "junkie/proto/udp.h"
#include "junkie/proto/dhcp.h"

#define BOOTPS_PORT 67

#undef LOG_CAT
#define LOG_CAT proto_dhcp_log_category

LOG_CATEGORY_DEF(proto_dhcp);

// Description of a DHCP header
struct dhcp {
    uint8_t op, htype, hlen, hops;
    uint32_t xid;
    uint16_t secs, flags;
    uint32_t ciaddr, yiaddr, siaddr, giaddr;
    unsigned char chaddr[16], sname[64], file[128];
    uint8_t cookie[4];
    uint8_t options[];
} packed_;

static uint8_t magic_cookie[] = { 99, 130, 83, 99 };

/*
 * Parse
 */

static char const *dhcp_opcode_2_str(enum dhcp_opcode opcode)
{
    switch (opcode) {
        case BOOTP_REQUEST: return "request";
        case BOOTP_REPLY:   return "reply";
    }
    assert(!"Unknown DHCP opcode");
    return "unknown";
}

static char const *dhcp_msg_type_2_str(enum dhcp_msg_type type)
{
    switch (type) {
        case DHCP_DISCOVER: return "discover";
        case DHCP_OFFER:    return "offer";
        case DHCP_REQUEST:  return "request";
        case DHCP_ACK:      return "ack";
        case DHCP_NAK:      return "nack";
        case DHCP_DECLINE:  return "decline";
        case DHCP_RELEASE:  return "release";
        case DHCP_INFORM:   return "inform";
    }
    assert(!"Invalid DHCP msg type");
    return "unknown";
}

static void const *dhcp_info_addr(struct proto_info const *info_, size_t *size)
{
    struct dhcp_proto_info const *info = DOWNCAST(info_, info, dhcp_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *dhcp_info_2_str(struct proto_info const *info_)
{
    struct dhcp_proto_info const *info = DOWNCAST(info_, info, dhcp_proto_info);
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "%s, opcode=%s, msg_type=%s, xid=0x%x, client_ip=%s, client_mac=%s, server=%s",
        proto_info_2_str(info_),
        dhcp_opcode_2_str(info->opcode),
        dhcp_msg_type_2_str(info->msg_type),
        info->xid,
        info->set_values & DHCP_CLIENT_SET ? ip_addr_2_str(&info->client) : "unset",
        info->hw_addr_is_eth ? eth_addr_2_str(info->client_mac) : "not eth",
        info->server_name[0] != '\0' ? info->server_name : "unset");

    return str;
}

static enum proto_parse_status dhcp_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct dhcp const *dhcp = (struct dhcp *)payload;

    // Sanity Checks

    // Check that we have at least the size of an DHCP packet for IP protocol
    if (wire_len < sizeof(*dhcp)) return PROTO_PARSE_ERR;
    // And that we have enough data to parse it
    if (cap_len < sizeof(*dhcp)) return PROTO_TOO_SHORT;

    if (0 != memcmp(dhcp->cookie, &magic_cookie, sizeof(magic_cookie))) {
        SLOG(LOG_DEBUG, "Bad magic Cookie");
        return PROTO_PARSE_ERR;
    }

    struct dhcp_proto_info info;
    proto_info_ctor(&info.info, parser, parent, wire_len, 0);
    info.opcode = READ_U8(&dhcp->op);
    if (info.opcode != BOOTP_REQUEST && info.opcode != BOOTP_REPLY) {
        SLOG(LOG_DEBUG, "Unknown DHCP opcode (%u)", info.opcode);
        return PROTO_PARSE_ERR;
    }
    uint8_t const hlen = READ_U8(&dhcp->hlen);
    if (hlen > sizeof(dhcp->chaddr)) {
        SLOG(LOG_DEBUG, "Bad hlen in DHCP (%u)", hlen);
        return PROTO_PARSE_ERR;
    }
    info.xid = READ_U32N(&dhcp->xid);
    info.set_values = 0;
    uint32_t const addr = READ_U32(&dhcp->yiaddr);
    if (addr) {
        info.set_values |= DHCP_CLIENT_SET;
        ip_addr_ctor_from_ip4(&info.client, addr);
    }
    uint8_t const htype = READ_U8(&dhcp->htype);
    info.hw_addr_is_eth = htype == 1;
    if (info.hw_addr_is_eth) {
        if (hlen != sizeof(info.client_mac)) {
            SLOG(LOG_DEBUG, "Bad hlen (%u) for Eth type", hlen);
            return PROTO_PARSE_ERR;
        }
        memcpy(info.client_mac, dhcp->chaddr, sizeof(info.client_mac));
    } else {
        memset(info.client_mac, 0, sizeof(info.client_mac));
    }

    memcpy(info.server_name, dhcp->sname, sizeof(info.server_name));

    SLOG(LOG_DEBUG, "New DHCP %s", dhcp_opcode_2_str(info.opcode));

    // parse options
    info.msg_type = 0;  // mandatory
    struct cursor c;
    cursor_ctor(&c, dhcp->options, cap_len - offsetof(struct dhcp, options));
    while (c.cap_len >= 2) {
        uint8_t const type = cursor_read_u8(&c);
        uint8_t const len  = cursor_read_u8(&c);
        if (c.cap_len < len) {
            SLOG(LOG_DEBUG, "Cannot read options");
            return PROTO_PARSE_ERR;
        }
        switch (type) {
            case 53:    // msg type
                if (len != 1) {
                    SLOG(LOG_DEBUG, "Bad length (%"PRIu8") for msg type DHCP option", len);
                    return PROTO_PARSE_ERR;
                }
                info.msg_type = cursor_read_u8(&c);
                if (info.msg_type > DHCP_INFORM) {
                    SLOG(LOG_DEBUG, "Bad DHCP msg type (%u)", info.msg_type);
                    return PROTO_PARSE_ERR;
                }
                break;
            default:
                cursor_drop(&c, len);
                break;
        }
    }
    if (0 == info.msg_type) {   // not found
        SLOG(LOG_DEBUG, "DHCP msg without msg type");
        return PROTO_PARSE_ERR;
    }

    return proto_parse(NULL, &info.info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
}

/*
 * Construction/Destruction
 */

static struct uniq_proto uniq_proto_dhcp;
struct proto *proto_dhcp = &uniq_proto_dhcp.proto;
static struct port_muxer dhcp_port_muxer;

void dhcp_init(void)
{
    log_category_proto_dhcp_init();

    static struct proto_ops const ops = {
        .parse       = dhcp_parse,
        .parser_new  = uniq_parser_new,
        .parser_del  = uniq_parser_del,
        .info_2_str  = dhcp_info_2_str,
        .info_addr   = dhcp_info_addr
    };
    uniq_proto_ctor(&uniq_proto_dhcp, &ops, "DHCP", PROTO_CODE_DHCP);
    port_muxer_ctor(&dhcp_port_muxer, &udp_port_muxers, BOOTPS_PORT, BOOTPS_PORT, proto_dhcp);
}

void dhcp_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    port_muxer_dtor(&dhcp_port_muxer, &udp_port_muxers);
    uniq_proto_dtor(&uniq_proto_dhcp);
#   endif
    log_category_proto_dhcp_fini();
}
