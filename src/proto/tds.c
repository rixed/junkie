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
#include <ctype.h>
#include "junkie/cpp.h"
#include "junkie/tools/log.h"
#include "junkie/tools/tempstr.h"
#include "junkie/tools/objalloc.h"
#include "junkie/proto/proto.h"
#include "junkie/proto/tcp.h"
#include "junkie/proto/sql.h"
#include "junkie/proto/streambuf.h"
#include "junkie/proto/cursor.h"

#undef LOG_CAT
#define LOG_CAT proto_tds_log_category

LOG_CATEGORY_DEF(proto_tds);

struct tds_parser {
    struct parser parser;
    unsigned c2s_way;       // The way when traffic is going from client to server (or UNSET)
    struct streambuf sbuf;
};

static parse_fun tds_sbuf_parse;

static int tds_parser_ctor(struct tds_parser *tds_parser, struct proto *proto)
{
    SLOG(LOG_DEBUG, "Constructing tds_parser@%p", tds_parser);
    assert(proto == proto_tds);
    if (0 != parser_ctor(&tds_parser->parser, proto)) return -1;
    tds_parser->c2s_way = UNSET;
    if (0 != streambuf_ctor(&tds_parser->sbuf, tds_sbuf_parse, 30000)) return -1;

    return 0;
}

static struct parser *tds_parser_new(struct proto *proto)
{
    struct tds_parser *tds_parser = objalloc_nice(sizeof(*tds_parser), "MySQL parsers");
    if (! tds_parser) return NULL;

    if (-1 == tds_parser_ctor(tds_parser, proto)) {
        objfree(tds_parser);
        return NULL;
    }

    return &tds_parser->parser;
}

static void tds_parser_dtor(struct tds_parser *tds_parser)
{
    SLOG(LOG_DEBUG, "Destructing tds_parser@%p", tds_parser);
    parser_dtor(&tds_parser->parser);
    streambuf_dtor(&tds_parser->sbuf);
}

static void tds_parser_del(struct parser *parser)
{
    struct tds_parser *tds_parser = DOWNCAST(parser, parser, tds_parser);
    tds_parser_dtor(tds_parser);
    objfree(tds_parser);
}

/*
 * Parse
 */

static enum proto_parse_status tds_sbuf_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct tds_parser *tds_parser = DOWNCAST(parser, parser, tds_parser);

    // If this is the first time we are called, init c2s_way
    if (tds_parser->c2s_way == UNSET) {
        tds_parser->c2s_way = way;
        SLOG(LOG_DEBUG, "First packet, init c2s_way to %u", tds_parser->c2s_way);
    }

    // Now build the proto_info
    struct sql_proto_info info;
    proto_info_ctor(&info.info, parser, parent, wire_len, 0);
    info.is_query = way == tds_parser->c2s_way;
    info.msg_type = SQL_UNKNOWN;
    info.set_values = 0;

    (void)payload;
    (void)cap_len;
    return proto_parse(NULL, &info.info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
}

static enum proto_parse_status tds_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct tds_parser *tds_parser = DOWNCAST(parser, parser, tds_parser);

    enum proto_parse_status const status = streambuf_add(&tds_parser->sbuf, parser, parent, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);

    return status;
}

/*
 * Construction/Destruction
 */

static struct proto proto_tds_;
struct proto *proto_tds = &proto_tds_;
static struct port_muxer tds_tcp_muxer;

void tds_init(void)
{
    log_category_proto_tds_init();

    static struct proto_ops const ops = {
        .parse       = tds_parse,
        .parser_new  = tds_parser_new,
        .parser_del  = tds_parser_del,
        .info_2_str  = sql_info_2_str,
        .info_addr   = sql_info_addr
    };
    proto_ctor(&proto_tds_, &ops, "TDS", PROTO_CODE_TDS);
    port_muxer_ctor(&tds_tcp_muxer, &tcp_port_muxers, 1433, 1433, proto_tds);
}

void tds_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    port_muxer_dtor(&tds_tcp_muxer, &tcp_port_muxers);
    proto_dtor(&proto_tds_);
#   endif
    log_category_proto_tds_fini();
}
