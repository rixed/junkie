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
#include <junkie/tools/tempstr.h>
#include <junkie/proto/ip.h>
#include <junkie/proto/icmp.h>
#include "proto/ip_hdr.h"

static char const Id[] = "$Id: cec9e9e404a6e9491b912c6adb58350490d49047 $";

#undef LOG_CAT
#define LOG_CAT proto_icmp_log_category

LOG_CATEGORY_DEF(proto_icmp);

/*
 * Proto Infos
 */

static char const *unreachable_code_2_str(uint8_t code)
{
    switch (code) {
        case 0:  return "NetUnreachable";
        case 1:  return "HostUnreachable";
        case 2:  return "ProtoUnreachable";
        case 3:  return "PortUnreachable";
        case 4:  return "NeedFragButCant";
        case 5:  return "CantRouteSource";
        case 6:  return "UnknownDestNet";
        case 7:  return "UnknownDestHost";
        case 8:  return "SrcHostAlone";
        case 9:  return "DestNetForbidden";
        case 10: return "DestHostForbidden";
        case 11: return "BadTOSforNet";
        case 12: return "BadTOSforHost";
        case 13: return "Filtered";
        case 14: return "PrecPolicyViolation";
        case 15: return "CurrentPrecCut";
    }

    return "Unreachable";
}

static char const *redirected_code_2_str(uint8_t code)
{
    switch (code) {
        case 0: return "NetRedirected";
        case 1: return "HostRedirected";
        case 2: return "TOSRedirectedForNet";
        case 3: return "TOSRedirectedForHost";
    }

    return "Redirected";
}

static char const *ttl_exceeded_code_2_str(uint8_t code)
{
    switch (code) {
        case 0: return "TTLReachedDuringTransit";
        case 1: return "TTLReachedDuringReassembly";
    }

    return "TTLReached";
}

static char const *syntax_err_code_2_str(uint8_t code)
{
    switch (code) {
        case 0: return "BadIPHeader";
        case 1: return "MissingRequiredOption";
    }

    return "SyntaxError";
}

static char const *icmp_type_2_str(uint8_t type, uint8_t code)
{
    switch (type) {
        case 0:  return "EchoReply";
        case 3:  return unreachable_code_2_str(code);
        case 4:  return "MaxThroughput";
        case 5:  return redirected_code_2_str(code);
        case 8:  return "EchoRequest";
        case 9:  return "GWReply";
        case 10: return "GWRequest";
        case 11: return ttl_exceeded_code_2_str(code);
        case 12: return syntax_err_code_2_str(code);
        case 13: return "TSRequest";
        case 14: return "TSReply";
        case 15: return "InfoRequest";
        case 16: return "InfoReply";
        case 17: return "NetMaskRequest";
        case 18: return "NetMaskReply";
    }

    return "UNKNOWN";
}

char *icmp_err_2_str(struct icmp_err const *err, unsigned set_values)
{
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "protocol=%"PRIu8", src=%s:%"PRIu16", dst=%s:%"PRIu16,
        err->protocol,
        ip_addr_2_str(err->addr+0),
        set_values & ICMP_ERR_PORT_SET ? err->port[0] : 0,
        ip_addr_2_str(err->addr+1),
        set_values & ICMP_ERR_PORT_SET ? err->port[1] : 0);
    return str;
}

static void const *icmp_info_addr(struct proto_info const *info_, size_t *size)
{
    struct icmp_proto_info const *info = DOWNCAST(info_, info, icmp_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *icmp_info_2_str(struct proto_info const *info_)
{
    struct icmp_proto_info const *info = DOWNCAST(info_, info, icmp_proto_info);
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "%s, type=%s, err=%s",
        proto_info_2_str(info_),
        icmp_type_2_str(info->type, info->code),
        info->set_values & ICMP_ERR_SET ? icmp_err_2_str(&info->err, info->set_values) : "NONE");

    return str;
}

static void icmp_proto_info_ctor(struct icmp_proto_info *info, struct parser *parser, struct proto_info *parent, size_t packet_len, uint8_t type, uint8_t code)
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

int icmp_extract_err_ports(struct icmp_err *err, uint8_t const *packet)
{
    memcpy(err->port, packet, sizeof(err->port));
    err->port[0] = ntohs(err->port[0]);
    err->port[1] = ntohs(err->port[1]);
    return 0;
}

static int icmp_extract_err_infos(struct icmp_proto_info *info, uint8_t const *packet, size_t packet_len)
{
    struct icmp_err *err = &info->err;

    if (packet_len < 20 + 8) {
        SLOG(LOG_DEBUG, "Bogus ICMP err: packet too short for IP header");
        return -1;
    }
    struct ip_hdr const *iphdr = (struct ip_hdr const *)packet;
    size_t iphdr_len = IP_HDR_LENGTH(iphdr);
    if (iphdr_len > packet_len - 8) {
        SLOG(LOG_DEBUG, "Bogus ICMP packet IP header too long (%zu > %zu)",
            iphdr_len, packet_len = 8);
        return -1;
    }

    err->protocol = READ_U8(&iphdr->protocol);
    ip_addr_ctor_from_ip4(err->addr+0, READ_U32(&iphdr->src));
    ip_addr_ctor_from_ip4(err->addr+1, READ_U32(&iphdr->dst));

    switch (err->protocol) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
            info->set_values |= ICMP_ERR_PORT_SET;
            return icmp_extract_err_ports(err, packet + iphdr_len);
        default:
            SLOG(LOG_DEBUG, "ICMP Error for unsuported protocol %u", err->protocol);
            return 0;
    }
}

static bool icmp_is_err(uint8_t type)
{
    switch (type) {
        case 0:
        case 8:
        case 9:
        case 10:
        case 13:
        case 14:
        case 15:
        case 16:
        case 17:
        case 18:
            return false;
    }
    return true;
}

static enum proto_parse_status icmp_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct icmp_hdr *icmphdr = (struct icmp_hdr *)packet;

    // Sanity checks
    if (wire_len < sizeof(*icmphdr)) return PROTO_PARSE_ERR;
    if (cap_len < sizeof(*icmphdr)) return PROTO_TOO_SHORT;

    struct icmp_proto_info info;
    icmp_proto_info_ctor(&info, parser, parent, wire_len, READ_U8(&icmphdr->type), READ_U8(&icmphdr->code));

    // Extract error values
    if (icmp_is_err(READ_U8(&icmphdr->type))) {
        if (0 == icmp_extract_err_infos(&info, packet + sizeof(*icmphdr), cap_len - sizeof(*icmphdr))) {
            info.set_values |= ICMP_ERR_SET;
        }
    }

    return proto_parse(NULL, &info.info, way, NULL, 0, 0, now, okfn, tot_cap_len, tot_packet);
}

/*
 * Init
 */

static struct uniq_proto uniq_proto_icmp;
struct proto *proto_icmp = &uniq_proto_icmp.proto;
static struct ip_subproto icmp_ip_subproto, icmp_ip6_subproto;

void icmp_init(void)
{
    log_category_proto_icmp_init();

    static struct proto_ops const ops = {
        .parse      = icmp_parse,
        .parser_new = uniq_parser_new,
        .parser_del = uniq_parser_del,
        .info_2_str = icmp_info_2_str,
        .info_addr  = icmp_info_addr,
    };
    uniq_proto_ctor(&uniq_proto_icmp, &ops, "ICMP");
    ip_subproto_ctor(&icmp_ip_subproto, IPPROTO_ICMP, proto_icmp);
    ip6_subproto_ctor(&icmp_ip6_subproto, IPPROTO_ICMP, proto_icmp);
}

void icmp_fini(void)
{
    ip_subproto_dtor(&icmp_ip_subproto);
    ip6_subproto_dtor(&icmp_ip6_subproto);
    uniq_proto_dtor(&uniq_proto_icmp);
    log_category_proto_icmp_fini();
}

