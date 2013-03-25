// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2013, SecurActive.
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
#include "junkie/tools/objalloc.h"
#include "junkie/proto/streambuf.h"
#include "junkie/proto/port_muxer.h"
#include "junkie/proto/tcp.h"
#include "junkie/proto/tls.h"

#undef LOG_CAT
#define LOG_CAT proto_tls_log_category

LOG_CATEGORY_DEF(proto_tls);

struct tls_parser {
    struct parser parser;
    unsigned c2s_way;       // The way when traffic is going from client to server (UNSET for unset)
    struct streambuf sbuf;
};

static parse_fun tls_sbuf_parse;

static int tls_parser_ctor(struct tls_parser *tls_parser, struct proto *proto)
{
    SLOG(LOG_DEBUG, "Constructing tls_parser@%p", tls_parser);
    assert(proto == proto_tls);
    if (0 != parser_ctor(&tls_parser->parser, proto)) return -1;
    tls_parser->c2s_way = UNSET;
#   define MAX_TLS_BUFFER (16383 + 5)
    if (0 != streambuf_ctor(&tls_parser->sbuf, tls_sbuf_parse, MAX_TLS_BUFFER)) return -1;

    return 0;
}

static struct parser *tls_parser_new(struct proto *proto)
{
    struct tls_parser *tls_parser = objalloc_nice(sizeof(*tls_parser), "TLS parsers");
    if (! tls_parser) return NULL;

    if (-1 == tls_parser_ctor(tls_parser, proto)) {
        objfree(tls_parser);
        return NULL;
    }

    return &tls_parser->parser;
}

static void tls_parser_dtor(struct tls_parser *tls_parser)
{
    SLOG(LOG_DEBUG, "Destructing tls_parser@%p", tls_parser);
    parser_dtor(&tls_parser->parser);
    streambuf_dtor(&tls_parser->sbuf);
}

static void tls_parser_del(struct parser *parser)
{
    struct tls_parser *tls_parser = DOWNCAST(parser, parser, tls_parser);
    tls_parser_dtor(tls_parser);
    objfree(tls_parser);
}

/*
 * Serialization
 */

static void const *tls_info_addr(struct proto_info const *info_, size_t *size)
{
    struct tls_proto_info const *info = DOWNCAST(info_, info, tls_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *tls_info_2_str(struct proto_info const *info_)
{
    struct tls_proto_info const *info = DOWNCAST(info_, info, tls_proto_info);
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "%s",
        proto_info_2_str(&info->info));
    return str;
}

static void tls_serialize(struct proto_info const *info_, uint8_t **buf)
{
    struct tls_proto_info const *info = DOWNCAST(info_, info, tls_proto_info);
    proto_info_serialize(&info->info, buf);
}

static void tls_deserialize(struct proto_info *info_, uint8_t const **buf)
{
    struct tls_proto_info *info = DOWNCAST(info_, info, tls_proto_info);
    proto_info_deserialize(&info->info, buf);
}


/*
 * Parsing
 */

static enum proto_parse_status tls_sbuf_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    (void)payload;
    (void)cap_len;

    struct tls_parser *tls_parser = DOWNCAST(parser, parser, tls_parser);

    // If this is the first time we are called, init c2s_way
    if (tls_parser->c2s_way == UNSET) {
        tls_parser->c2s_way = !way;
        SLOG(LOG_DEBUG, "First packet, init c2s_way to %u", tls_parser->c2s_way);
    }

    // Now build the proto_info
    struct tls_proto_info info;
    proto_info_ctor(&info.info, parser, parent, wire_len, 0);

    return proto_parse(NULL, &info.info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
}


static enum proto_parse_status tls_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct tls_parser *tls_parser = DOWNCAST(parser, parser, tls_parser);

    enum proto_parse_status const status = streambuf_add(&tls_parser->sbuf, parser, parent, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);

    return status;
}

/*
 * Initialization
 */

static struct proto proto_tls_;
struct proto *proto_tls = &proto_tls_;
static struct port_muxer tcp_port_muxer;

void tls_init(void)
{
    log_category_proto_tls_init();

    static struct proto_ops const ops = {
        .parse       = tls_parse,
        .parser_new  = tls_parser_new,
        .parser_del  = tls_parser_del,
        .info_2_str  = tls_info_2_str,
        .info_addr   = tls_info_addr,
        .serialize   = tls_serialize,
        .deserialize = tls_deserialize,
    };
    proto_ctor(&proto_tls_, &ops, "TLS", PROTO_CODE_TLS);
    port_muxer_ctor(&tcp_port_muxer, &tcp_port_muxers, 443, 443, proto_tls);
}

void tls_fini(void)
{
    port_muxer_dtor(&tcp_port_muxer, &tcp_port_muxers);

    proto_dtor(&proto_tls_);
    log_category_proto_tls_fini();
}
