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
#include <assert.h>
#include "junkie/tools/objalloc.h"
#include "junkie/proto/udp.h"
#include "junkie/proto/gtp.h"

#undef LOG_CAT
#define LOG_CAT proto_gtp_log_category

LOG_CATEGORY_DEF(proto_gtp);

struct gtp_parser {
    struct parser parser;
};

static int gtp_parser_ctor(struct gtp_parser *gtp_parser, struct proto unused_ *proto)
{
    assert(proto == proto_gtp);
    if (0 != parser_ctor(&gtp_parser->parser, proto_gtp)) {
        return -1;
    }
    return 0;
}

static struct parser *gtp_parser_new(struct proto *proto)
{
    struct gtp_parser *gtp_parser = objalloc_nice(sizeof(*gtp_parser), "GTP parsers");
    if (! gtp_parser) return NULL;

    if (-1 == gtp_parser_ctor(gtp_parser, proto)) {
        objfree(gtp_parser);
        return NULL;
    }

    return &gtp_parser->parser;
}

static void gtp_parser_dtor(struct gtp_parser *gtp_parser)
{
    parser_dtor(&gtp_parser->parser);
}

static void gtp_parser_del(struct parser *parser)
{
    struct gtp_parser *gtp_parser = DOWNCAST(parser, parser, gtp_parser);
    gtp_parser_dtor(gtp_parser);
    objfree(gtp_parser);
}

/*
 * proto_info
 */

static void const *gtp_info_addr(struct proto_info const *info_, size_t *size)
{
    struct gtp_proto_info const *info = DOWNCAST(info_, info, gtp_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *gtp_info_2_str(struct proto_info const *info_)
{
    struct gtp_proto_info const unused_ *info = DOWNCAST(info_, info, gtp_proto_info);
    return proto_info_2_str(info_);
}

static void gtp_proto_info_ctor(struct gtp_proto_info *info, struct parser *parser, struct proto_info *parent, size_t head_len, size_t payload)
{
    proto_info_ctor(&info->info, parser, parent, head_len, payload);
}

/*
 * Parse
 */

static enum proto_parse_status gtp_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const unused_ *packet, size_t unused_ cap_len, size_t unused_ wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct gtp_parser unused_ *gtp_parser = DOWNCAST(parser, parser, gtp_parser);
    struct gtp_proto_info info;

    gtp_proto_info_ctor(&info, parser, parent, 0, wire_len);

    // No subparser for now:
    (void)proto_parse(NULL, &info.info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);

    return PROTO_OK;
}

/*
 * Init
 */

static struct proto proto_gtp_;
struct proto *proto_gtp = &proto_gtp_;
static struct port_muxer udp_port_muxer_userdata;  // GTP-u
static struct port_muxer udp_port_muxer_control;   // GTP-c

void gtp_init(void)
{
    log_category_proto_gtp_init();

    static struct proto_ops const ops = {
        .parse       = gtp_parse,
        .parser_new  = gtp_parser_new,
        .parser_del  = gtp_parser_del,
        .info_2_str  = gtp_info_2_str,
        .info_addr   = gtp_info_addr
    };
    proto_ctor(&proto_gtp_, &ops, "GTP", PROTO_CODE_GTP);
    port_muxer_ctor(&udp_port_muxer_userdata, &udp_port_muxers, 2152, 2152, proto_gtp);
    port_muxer_ctor(&udp_port_muxer_control, &udp_port_muxers, 2123, 2123, proto_gtp);
}

void gtp_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    port_muxer_dtor(&udp_port_muxer_userdata, &udp_port_muxers);
    port_muxer_dtor(&udp_port_muxer_control, &udp_port_muxers);
    proto_dtor(&proto_gtp_);
#   endif
    log_category_proto_gtp_fini();
}
