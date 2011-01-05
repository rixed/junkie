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
#include <assert.h>
#include <stdint.h>
#include <junkie/cpp.h>
#include <junkie/tools/log.h>
#include <junkie/proto/proto.h>
#include <junkie/proto/netbios.h>
#include <junkie/proto/cifs.h>

static char const Id[] = "$Id: 9ceb049707094753513467be6533a0d5f6b886bb $";

#undef LOG_CAT
#define LOG_CAT proto_netbios_log_category

LOG_CATEGORY_DEF(proto_netbios);

#define NETBIOS_SESSION_MESSAGE 0x00 /* unused yet */
#define NETBIOS_HEADER_SIZE 4


static int packet_is_netbios(uint8_t const *packet, size_t next_len)
{
    uint32_t len = *(uint32_t *)packet & 0x0fff;

    return len == next_len;
}

static void const *netbios_info_addr(struct proto_info const *info_, size_t *size)
{
    struct netbios_proto_info const *info = DOWNCAST(info_, info, netbios_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *netbios_info_2_str(struct proto_info const unused_ *info)
{
    return "TODO";
}

static void netbios_proto_info_ctor(struct netbios_proto_info *info, struct parser *parser, struct proto_info *parent, size_t header, size_t payload)
{
    proto_info_ctor(&info->info, parser, parent, header, payload);
    info->mode = NETBIOS_CIFS;
}


static enum proto_parse_status netbios_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn)
{
    /* Sanity checks */
    if (wire_len < NETBIOS_HEADER_SIZE) return PROTO_PARSE_ERR;
    if (cap_len < NETBIOS_HEADER_SIZE) return PROTO_TOO_SHORT;

    if (! packet_is_netbios(packet, cap_len)) return PROTO_PARSE_ERR;

    /* Parse */
    struct netbios_proto_info info;
    netbios_proto_info_ctor(&info, parser, parent, NETBIOS_HEADER_SIZE, wire_len - NETBIOS_HEADER_SIZE);

    uint8_t const *next_packet = packet + NETBIOS_HEADER_SIZE;
    struct parser *subparser = proto_cifs->ops->parser_new(proto_cifs, now);
    if (! subparser) goto fallback;

    /* List of protocols above NetBios: CIFS, SMB, ... */
    int err = proto_parse(subparser, parent, way, next_packet, cap_len - NETBIOS_HEADER_SIZE, wire_len - NETBIOS_HEADER_SIZE, now, okfn);
    parser_unref(subparser);
    if (err) goto fallback;
    return PROTO_OK;

fallback:
    (void)proto_parse(NULL, parent, way, next_packet, cap_len - NETBIOS_HEADER_SIZE, wire_len - NETBIOS_HEADER_SIZE, now, okfn);
    return PROTO_OK;
}


/*
 * Initialization
 */

static struct uniq_proto uniq_proto_netbios;
struct proto *proto_netbios = &uniq_proto_netbios.proto;

void netbios_init(void)
{
    log_category_proto_netbios_init();

    static struct proto_ops const ops = {
        .parse      = netbios_parse,
        .parser_new = uniq_parser_new,
        .parser_del = uniq_parser_del,
        .info_2_str = netbios_info_2_str,
        .info_addr  = netbios_info_addr,
    };
    uniq_proto_ctor(&uniq_proto_netbios, &ops, "Netbios");
}

void netbios_fini(void)
{
    uniq_proto_dtor(&uniq_proto_netbios);
    log_category_proto_netbios_fini();
}
