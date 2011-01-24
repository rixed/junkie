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
#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <junkie/tools/ip_addr.h>
#include <junkie/tools/tempstr.h>
#include <junkie/tools/mallocer.h>
#include <junkie/proto/rtcp.h>
#include <junkie/proto/sdp.h>
#include <junkie/proto/udp.h>
#include <junkie/proto/ip.h>
#include <junkie/proto/rtp.h>
#include "proto/liner.h"
#include "proto/sdper.h"

static char const Id[] = "$Id: e9dc9dbf074ba863e946d13272c7f7ea15581dd6 $";

#undef LOG_CAT
#define LOG_CAT proto_sdp_log_category

LOG_CATEGORY_DEF(proto_sdp);

#define SDP_TIMEOUT (5 * 60)

struct sdp_parser {
    struct parser parser;
    // We remember the first host/port seen in order to init conntracking when the other one is received
    bool host_set, sender_set;  // sender_set is only meaningfull when host_set
    struct ip_addr host;    // the advertized IP
    uint16_t port;          // the advertized port
    struct ip_addr sender;  // the actual IP sending the advertisment
};

/*
 * Proto Infos
 */

static void const *sdp_info_addr(struct proto_info const *info_, size_t *size)
{
    struct sdp_proto_info const *info = DOWNCAST(info_, info, sdp_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *sdp_info_2_str(struct proto_info const *info_)
{
    struct sdp_proto_info const *info = DOWNCAST(info_, info, sdp_proto_info);
    char *str = tempstr();

    snprintf(str, TEMPSTR_SIZE, "%s, host=%s, port=%s",
             proto_info_2_str(info_),
             info->set_values & SDP_HOST_SET ? ip_addr_2_str(&info->host) : "unset",
             info->set_values & SDP_PORT_SET ? tempstr_printf("%u", info->port) : "unset");

    return str;
}

static void sdp_proto_info_ctor(struct sdp_proto_info *info, struct parser *parser, struct proto_info *parent, size_t head_len, size_t payload)
{
    memset(info, 0, sizeof *info);
    proto_info_ctor(&info->info, parser, parent, head_len, payload);
}

/*
 * Parse
 */

static int sdp_extract_host(unsigned unused_ cmd, struct liner *liner, void *info_)
{
    struct sdp_proto_info *info = info_;

#define IN_IP "IN IP"
#define IN_IP_LEN strlen(IN_IP)

    if (liner_tok_length(liner) < IN_IP_LEN)
        return -1;

    if (strncasecmp(liner->start, IN_IP, IN_IP_LEN))
        return -1;

    char const *start = liner->start + IN_IP_LEN;
    int version = start[0] - '0';
    if (version != 4 && version != 6) {
        SLOG(LOG_DEBUG, "Bogus IP version (%d)", version);
        return -1;
    }

    struct liner space_liner;
    liner_init(&space_liner, &delim_spaces, (char const *)start, liner_tok_length(liner) - IN_IP_LEN);
    liner_next(&space_liner);   // skipping the IP version number

#undef IN_IP
#undef IN_IP_LEN

    if (0 != ip_addr_ctor_from_str(&info->host, space_liner.start, liner_tok_length(&space_liner), version))
        return -1;

    info->set_values |= SDP_HOST_SET;

    SLOG(LOG_DEBUG, "host found (%s)", ip_addr_2_str(&info->host));
    return 0;
}

static int sdp_extract_port(unsigned unused_ cmd, struct liner *liner, void *info_)
{
    struct sdp_proto_info *info = info_;

    // In case several medias are advertised, we are interrested only in the first one.
    // FIXME: parse all m= stenzas with their respective attributes (a=).
    if (info->set_values & SDP_PORT_SET) return 0;

    // skip the media format ("audio", ...)
    struct liner space_liner;

    liner_init(&space_liner, &delim_spaces, (char const *)liner->start, liner_tok_length(liner));
    liner_next(&space_liner);

    char const *end;
    info->port = liner_strtoull(&space_liner, &end, 10);
    if (!info->port) // unable to extract an integer value
        return -1;

    info->set_values |= SDP_PORT_SET;
    SLOG(LOG_DEBUG, "port found (%"PRIu16")", info->port);
    return 0;
}

static void spawn_subparsers(struct ip_addr const *this_host, uint16_t this_port, struct ip_addr const *other_host, uint16_t other_port, struct proto_info *parent, struct timeval const *now)
{
    ASSIGN_INFO_CHK(ip, parent, );

    SLOG(LOG_DEBUG, "Spawning RT(C)P parsers for %s:%"PRIu16"<->%s:%"PRIu16, ip_addr_2_str(this_host), this_port, ip_addr_2_str(other_host), other_port);

    unsigned way2;
    struct mux_subparser *udp_parser =
        ip_subparser_lookup(ip->info.parser, proto_udp, NULL, IPPROTO_UDP, this_host, other_host, &way2, now);

    if (! udp_parser) return;

    // Notice that we request RT(C)P on behalf of our parent
    (void)udp_subparser_and_parser_new(udp_parser->parser, proto_rtp,  parent->parser, this_port,   other_port,   way2, now); // rtp conntrack
    (void)udp_subparser_and_parser_new(udp_parser->parser, proto_rtcp, parent->parser, this_port+1, other_port+1, way2, now); // rtcp conntrack
}

static enum proto_parse_status sdp_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct sdp_parser *sdp_parser = DOWNCAST(parser, parser, sdp_parser);

    static struct sdper_field const fields[] = {
        { 1, "c", sdp_extract_host },
        { 1, "m", sdp_extract_port },
    };

    static struct sdper const sdper = {
        .nb_fields = NB_ELEMS(fields),
        .fields = fields
    };

    SLOG(LOG_DEBUG, "Starting SDP analysis");

    /* Parse */

    struct sdp_proto_info info;
    sdp_proto_info_ctor(&info, parser, parent, wire_len, 0);

    if (0 != sdper_parse(&sdper, &cap_len, packet, cap_len, &info)) return PROTO_PARSE_ERR;

    if (
        (info.set_values & SDP_PORT_SET) &&
        (info.set_values & SDP_HOST_SET)
    ) {
        SLOG(LOG_DEBUG, "SDP@%p, connect info is %s:%"PRIu16, sdp_parser, ip_addr_2_str(&info.host), info.port);

        if (! sdp_parser->host_set) {
            sdp_parser->host_set = true;
            sdp_parser->host = info.host;
            sdp_parser->port = info.port;
            ASSIGN_INFO_OPT(ip, parent);
            if (ip) {
                sdp_parser->sender = ip->key.addr[0];
                sdp_parser->sender_set = true;
            } else {
                sdp_parser->sender_set = false;
            }
        } else if (0 != ip_addr_cmp(&sdp_parser->host, &info.host)) {
            // Start conntracking between the advertized hosts
            spawn_subparsers(&sdp_parser->host, sdp_parser->port, &info.host, info.port, parent, now);

            ASSIGN_INFO_OPT(ip, parent);
            bool may_use_stun[2] = {
                0 != ip_addr_cmp(&sdp_parser->sender, &sdp_parser->host),
                ip && 0 != ip_addr_cmp(&ip->key.addr[0], &info.host),
            };
            // If the sender IP was different from the advertized host, start conntracking on this socket also
            if (may_use_stun[0]) {
                spawn_subparsers(&sdp_parser->sender, sdp_parser->port, &info.host, info.port, parent, now);
            }
            // If _this_ sender IP is different from this advertized host, start conntracking on this socket as well
            if (may_use_stun[1]) {
                spawn_subparsers(&sdp_parser->host, sdp_parser->port, &ip->key.addr[0], info.port, parent, now);
            }
            // If both senders IP were different from advertized ones then start conntracking between these two senders IP as well
            if (may_use_stun[0] && may_use_stun[1]) {
                spawn_subparsers(&sdp_parser->sender, sdp_parser->port, &ip->key.addr[0], info.port, parent, now);
            }

            // TODO: terminate this parser. meanwhile, reset its state :
            sdp_parser->host_set = false;
            sdp_parser->sender_set = false;
        }
    }

    return proto_parse(NULL, &info.info, way, NULL, 0, 0, now, okfn, tot_cap_len, tot_packet);
}

/*
 * Init
 */

static struct proto proto_sdp_;
struct proto *proto_sdp = &proto_sdp_;

static int sdp_parser_ctor(struct sdp_parser *sdp_parser, struct proto *proto, struct timeval const *now)
{
    assert(proto == proto_sdp);
    if (0 != parser_ctor(&sdp_parser->parser, proto, now)) {
        return -1;
    }

    sdp_parser->host_set = false;
    sdp_parser->sender_set = false;

    return 0;
}

static struct parser *sdp_parser_new(struct proto *proto, struct timeval const *now)
{
    MALLOCER(sdp_parsers);
    struct sdp_parser *sdp_parser = MALLOC(sdp_parsers, sizeof *sdp_parser);

    if (-1 == sdp_parser_ctor(sdp_parser, proto, now)) {
        FREE(sdp_parser);
        return NULL;
    }

    return &sdp_parser->parser;
}

static void sdp_parser_del(struct parser *parser)
{
    struct sdp_parser *sdp_parser = DOWNCAST(parser, parser, sdp_parser);

    parser_dtor(parser);
    FREE(sdp_parser);
}

void sdp_init(void)
{
    log_category_proto_sdp_init();

    static struct proto_ops const ops = {
        .parse      = sdp_parse,
        .parser_new = sdp_parser_new,
        .parser_del = sdp_parser_del,
        .info_2_str = sdp_info_2_str,
        .info_addr  = sdp_info_addr,
    };
    proto_ctor(&proto_sdp_, &ops, "SDP", SDP_TIMEOUT);
}

void sdp_fini(void)
{
    proto_dtor(&proto_sdp_);
    log_category_proto_sdp_fini();
}
