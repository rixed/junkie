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
#include <stdbool.h>
#include <assert.h>
#include <inttypes.h>
#include "junkie/cpp.h"
#include "junkie/tools/ext.h"
#include "junkie/tools/log.h"
#include "junkie/proto/serialize.h"
#include "junkie/proto/cnxtrack.h"
#include "junkie/proto/tcp.h"
#include "junkie/proto/udp.h"
#include "junkie/proto/discovery.h"

#undef LOG_CAT
#define LOG_CAT proto_discovery_log_category

LOG_CATEGORY_DEF(proto_discovery);

/*
 * Proto Infos
 */

char const *discovery_protocol_2_str(enum discovery_protocol p)
{
    switch (p) {
        case DISC_SSL_v2:  return "SSLv2";
        case DISC_SSL_v3:  return "SSLv3";
        case DISC_SSL_TLS: return "TLS";
        case DISC_BITTORRENT: return "bittorrent";
        case DISC_GNUTELLA:   return "gnutella";
    }
    assert(!"Invalid discovery_protocol");
}

static char const *discovery_trust_2_str(enum discovery_trust t)
{
    switch (t) {
        case DISC_HIGH:   return "high";
        case DISC_MEDIUM: return "medium";
        case DISC_LOW:    return "low";
    }
    assert(!"Invalid discovery_trust");
}

static void const *discovery_info_addr(struct proto_info const *info_, size_t *size)
{
    struct discovery_proto_info const *info = DOWNCAST(info_, info, discovery_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *discovery_info_2_str(struct proto_info const *info_)
{
    struct discovery_proto_info const *info = DOWNCAST(info_, info, discovery_proto_info);
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "%s, protocol=%s, trust=%s",
        proto_info_2_str(info_),
        discovery_protocol_2_str(info->protocol),
        discovery_trust_2_str(info->trust));
    return str;
}

static void discovery_serialize(struct proto_info const *info_, uint8_t **buf)
{
    struct discovery_proto_info const *info = DOWNCAST(info_, info, discovery_proto_info);
    proto_info_serialize(info_, buf);
    serialize_1(buf, info->protocol);
    serialize_1(buf, info->trust);
}

static void discovery_deserialize(struct proto_info *info_, uint8_t const **buf)
{
    struct discovery_proto_info *info = DOWNCAST(info_, info, discovery_proto_info);
    proto_info_deserialize(info_, buf);
    info->protocol = deserialize_1(buf);
    info->trust    = deserialize_1(buf);
}

/*
 * Parse
 */

static enum proto_parse_status discovery_parse(struct parser unused_ *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    // TODO
    (void)proto_parse(NULL, parent, way, packet, cap_len, wire_len, now, tot_cap_len, tot_packet);
    return PROTO_OK;
}

/*
 * Construction/Destruction
 */

static struct uniq_proto uniq_proto_discovery;
struct proto *proto_discovery = &uniq_proto_discovery.proto;
static struct port_muxer tcp_port_muxer;
static struct port_muxer udp_port_muxer;

void discovery_init(void)
{
    log_category_proto_discovery_init();

    static struct proto_ops const ops = {
        .parse       = discovery_parse,
        .parser_new  = uniq_parser_new,
        .parser_del  = uniq_parser_del,
        .info_2_str  = discovery_info_2_str,
        .info_addr   = discovery_info_addr,
        .serialize   = discovery_serialize,
        .deserialize = discovery_deserialize,
    };
    uniq_proto_ctor(&uniq_proto_discovery, &ops, "Protocol Discovery", PROTO_CODE_DISCOVERY);
    port_muxer_ctor(&tcp_port_muxer, &tcp_port_muxers, 1024, 65535, proto_discovery);
    port_muxer_ctor(&udp_port_muxer, &udp_port_muxers, 1024, 65535, proto_discovery);
}

void discovery_fini(void)
{
    port_muxer_dtor(&udp_port_muxer, &udp_port_muxers);
    port_muxer_dtor(&tcp_port_muxer, &tcp_port_muxers);
    uniq_proto_dtor(&uniq_proto_discovery);
    log_category_proto_discovery_fini();
}
