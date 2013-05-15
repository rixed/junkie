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
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include "junkie/proto/serialize.h"
#include "junkie/proto/tcp.h"
#include "junkie/proto/skinny.h"

#undef LOG_CAT
#define LOG_CAT proto_skinny_log_category

LOG_CATEGORY_DEF(proto_skinny);

#define SKINNY_PORT 2000

/*
 * Proto Infos
 */

static void const *skinny_info_addr(struct proto_info const *info_, size_t *size)
{
    struct skinny_proto_info const *info = DOWNCAST(info_, info, skinny_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *skinny_info_2_str(struct proto_info const *info_)
{
    struct skinny_proto_info const *info = DOWNCAST(info_, info, skinny_proto_info);
    return tempstr_printf("%s",
        proto_info_2_str(&info->info));
}

static void skinny_serialize(struct proto_info const *info_, uint8_t **buf)
{
    struct skinny_proto_info const *info = DOWNCAST(info_, info, skinny_proto_info);
    proto_info_serialize(&info->info, buf);
}

static void skinny_deserialize(struct proto_info *info_, uint8_t const **buf)
{
    struct skinny_proto_info *info = DOWNCAST(info_, info, skinny_proto_info);
    proto_info_deserialize(&info->info, buf);
}

static void skinny_proto_info_ctor(struct skinny_proto_info *info, struct parser *parser, struct proto_info *parent, size_t head_len, size_t payload)
{
    proto_info_ctor(&info->info, parser, parent, head_len, payload);
}

/*
 * Parse
 */

static enum proto_parse_status skinny_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    size_t payload = 0;
    // Parse one message (in case of piggybacking, will call ourself recursively so that subscribers are called once for each msg)
    struct skinny_proto_info info;
    skinny_proto_info_ctor(&info, parser, parent, payload, 0);

    (void)packet;
    (void)cap_len;
    (void)wire_len;

    (void)proto_parse(NULL, &info.info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
    return PROTO_OK;
}

/*
 * Init
 */

static struct uniq_proto uniq_proto_skinny;
struct proto *proto_skinny = &uniq_proto_skinny.proto;
static struct port_muxer tcp_port_muxer;

void skinny_init(void)
{
    log_category_proto_skinny_init();

    static struct proto_ops const ops = {
        .parse       = skinny_parse,
        .parser_new  = uniq_parser_new,
        .parser_del  = uniq_parser_del,
        .info_2_str  = skinny_info_2_str,
        .info_addr   = skinny_info_addr,
        .serialize   = skinny_serialize,
        .deserialize = skinny_deserialize,
    };
    uniq_proto_ctor(&uniq_proto_skinny, &ops, "SKINNY", PROTO_CODE_SKINNY);
    port_muxer_ctor(&tcp_port_muxer, &tcp_port_muxers, SKINNY_PORT, SKINNY_PORT, proto_skinny);
}

void skinny_fini(void)
{
    port_muxer_dtor(&tcp_port_muxer, &tcp_port_muxers);
    uniq_proto_dtor(&uniq_proto_skinny);
    log_category_proto_skinny_fini();
}

