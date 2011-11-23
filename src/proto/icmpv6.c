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
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "junkie/tools/tempstr.h"
#include "junkie/proto/icmp.h"
#include "junkie/proto/ip.h"
#include "proto/ip_hdr.h"

static char const icmpv6_Id[] = "$Id: be896b1f62e312d5d97d8f01af293f1a9fd19294 $";

#undef LOG_CAT
#define LOG_CAT proto_icmpv6_log_category

LOG_CATEGORY_DEF(proto_icmpv6);

/*
 * Proto Infos
 */

static char const *icmpv6_type_2_str(uint8_t type)
{
    switch (type) {
        case 1:   return "DestUnreachable";
        case 2:   return "PacketTooBig";
        case 3:   return "TimeExceeded";
        case 4:   return "BadParameter";
        case 128: return "EchoRequest";
        case 129: return "EchoReply";
        case 130: return "MulticastListenerQuery";
        case 131: return "MulticastListenerReport";
        case 132: return "MulticastListenerDone";
        case 133: return "RouterSolicitation";
        case 134: return "RouterAdvertisement";
        case 135: return "NeighborSolicitation";
        case 136: return "NeighborAdvertisement";
        case 137: return "RedirectMessage";
        case 138: return "RouterRenumbering";
        case 139: return "NodeInformationQuery";
        case 140: return "NodeInformationResponse";
        case 141: return "InverseNeighborDiscoverySolicitationMessage";
        case 142: return "InverseNeighborDiscoveryAdvertisementMessage";
        case 143: return "V2MulticastListenerReport";
        case 144: return "HomeAgentAddressDiscoveryRequestMessage";
        case 145: return "HomeAgentAddressDiscoveryReplyMessage";
        case 146: return "MobilePrefixSolicitation";
        case 147: return "MobilePrefixAdvertisement";
        case 148: return "CertificationPathSolicitationMessage";
        case 149: return "CertificationPathAdvertisementMessage";
        case 151: return "MulticastRouterAdvertisement";
        case 152: return "MulticastRouterSolicitation";
        case 153: return "MulticastRouterTermination";
        case 154: return "FMIPv6Messages";
        case 155: return "RPLControlMessage";
    }

    return "UNKNOWN";
}

static void const *icmpv6_info_addr(struct proto_info const *info_, size_t *size)
{
    struct icmp_proto_info const *info = DOWNCAST(info_, info, icmp_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

// Not the same than ICMP(v4) since the error codes are different.
static char const *icmpv6_info_2_str(struct proto_info const *info_)
{
    struct icmp_proto_info const *info = DOWNCAST(info_, info, icmp_proto_info);
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "%s, type=%s, code=%"PRIu8", err=%s, id=%d",
        proto_info_2_str(info_),
        icmpv6_type_2_str(info->type), info->code,
        info->set_values & ICMP_ERR_SET ? icmp_err_2_str(&info->err, info->set_values) : "NONE",
        info->set_values & ICMP_ID_SET ? info->id : -1);

    return str;
}

static void icmpv6_proto_info_ctor(struct icmp_proto_info *info, struct parser *parser, struct proto_info *parent, size_t packet_len, uint8_t type, uint8_t code)
{
    proto_info_ctor(&info->info, parser, parent, packet_len, 0);
    info->type = type;
    info->code = code;
    info->set_values = 0;
    // Err fields are extracted later
}

/*
 * Parse
 */

static int icmpv6_extract_err_infos(struct icmp_proto_info *info, uint8_t const *packet, size_t packet_len)
{
    struct icmp_err *err = &info->err;
    struct ipv6_hdr const *iphdr = (struct ipv6_hdr *)packet;

    if (packet_len < sizeof(*iphdr)) {
        SLOG(LOG_DEBUG, "Bogus ICMPv6 packet too short for IPv6 header");
        return -1;
    }

    err->protocol = READ_U8(&iphdr->next);
    ip_addr_ctor_from_ip6(err->addr+0, &iphdr->src);
    ip_addr_ctor_from_ip6(err->addr+1, &iphdr->dst);

    switch (iphdr->next) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
            if (packet_len >= sizeof(*iphdr) + 4) {
                info->set_values |= ICMP_ERR_PORT_SET;
                return icmp_extract_err_ports(err, packet + sizeof(*iphdr));
            }
        default:
            SLOG(LOG_DEBUG, "ICMPv6 Error for unsuported protocol %u", iphdr->next);
            return 0;
    }
}

static bool icmpv6_is_err(uint8_t type)
{
    return !(type & 0x80);
}

static bool icmpv6_has_id(uint8_t type)
{
    switch (type) {
        case 128:
        case 129:
            return true;
        // and probably others as well...
    }
    return false;
}

static enum proto_parse_status icmpv6_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct icmp_hdr *icmphdr = (struct icmp_hdr *)packet;

    // Sanity checks
    if (wire_len < sizeof(*icmphdr)) return PROTO_PARSE_ERR;
    if (cap_len < sizeof(*icmphdr)) return PROTO_TOO_SHORT;

    struct icmp_proto_info info;
    uint8_t const type = READ_U8(&icmphdr->type);
    icmpv6_proto_info_ctor(&info, parser, parent, wire_len, type, READ_U8(&icmphdr->code));

    if (icmpv6_has_id(type)) {
        info.set_values |= ICMP_ID_SET;
        info.id = READ_U16N(&icmphdr->id);
    }

    // Extract error values
    if (icmpv6_is_err(type)) {
        if (0 == icmpv6_extract_err_infos(&info, packet + sizeof(*icmphdr), cap_len - sizeof(*icmphdr))) {
            info.set_values |= ICMP_ERR_SET;
        }
    }

    return proto_parse(NULL, &info.info, way, NULL, 0, 0, now, okfn, tot_cap_len, tot_packet);
}

/*
 * Init
 */

static struct uniq_proto uniq_proto_icmpv6;
struct proto *proto_icmpv6 = &uniq_proto_icmpv6.proto;
static struct ip_subproto icmpv6_ip6_subproto;

void icmpv6_init(void)
{
    log_category_proto_icmpv6_init();

    static struct proto_ops const ops = {
        .parse       = icmpv6_parse,
        .parser_new  = uniq_parser_new,
        .parser_del  = uniq_parser_del,
        .info_2_str  = icmpv6_info_2_str,
        .info_addr   = icmpv6_info_addr,
        .serialize   = icmp_serialize,
        .deserialize = icmp_deserialize,
    };
    uniq_proto_ctor(&uniq_proto_icmpv6, &ops, "ICMPv6", PROTO_CODE_ICMP /* since we share the same info struct */);
    ip6_subproto_ctor(&icmpv6_ip6_subproto, IPPROTO_ICMPV6, proto_icmpv6);
}

void icmpv6_fini(void)
{
    ip6_subproto_dtor(&icmpv6_ip6_subproto);
    uniq_proto_dtor(&uniq_proto_icmpv6);
    log_category_proto_icmpv6_fini();
}
