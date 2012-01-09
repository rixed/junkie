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
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <assert.h>
#include "junkie/cpp.h"
#include "junkie/tools/log.h"
#include "junkie/tools/tempstr.h"
#include "junkie/proto/serialize.h"
#include "junkie/proto/proto.h"
#include "junkie/proto/eth.h"
#include "junkie/proto/cap.h"
#include "junkie/tools/ext.h"
#include "pkt_source.h"

#undef LOG_CAT
#define LOG_CAT proto_capture_log_category

LOG_CATEGORY_DEF(proto_capture);

bool collapse_ifaces = true;
EXT_PARAM_RW(collapse_ifaces, "collapse-ifaces", bool, "Set to true if packets from distinct ifaces share the same address range");
static const uint8_t zero = 0; // When collapsing devices we use this fake device id

/*
 * Proto Infos
 */

static void const *cap_info_addr(struct proto_info const *info_, size_t *size)
{
    struct cap_proto_info const *info = DOWNCAST(info_, info, cap_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *cap_info_2_str(struct proto_info const *info_)
{
    struct cap_proto_info const *info = DOWNCAST(info_, info, cap_proto_info);
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "%s, dev_id=%u, tv=%s",
        proto_info_2_str(info_),
        info->dev_id,
        timeval_2_str(&info->tv));
    return str;
}

static void cap_serialize(struct proto_info const *info_, uint8_t **buf)
{
    struct cap_proto_info const *info = DOWNCAST(info_, info, cap_proto_info);
    proto_info_serialize(info_, buf);
    serialize_2(buf, info->dev_id);
    timeval_serialize(&info->tv, buf);
}

static void cap_deserialize(struct proto_info *info_, uint8_t const **buf)
{
    struct cap_proto_info *info = DOWNCAST(info_, info, cap_proto_info);
    proto_info_deserialize(info_, buf);
    info->dev_id = deserialize_2(buf);
    timeval_deserialize(&info->tv, buf);
}

static void cap_proto_info_ctor(struct cap_proto_info *info, struct parser *parser, struct proto_info *parent, struct frame const *frame)
{
    proto_info_ctor(&info->info, parser, parent, sizeof(*frame), frame->wire_len);

    info->dev_id = collapse_ifaces ? zero : frame->pkt_source->dev_id;
    info->tv = frame->tv;
}

/*
 * Parser
 */

struct mux_subparser *cap_subparser_and_parser_new(struct parser *parser, struct proto *proto, struct proto *requestor, uint8_t dev_id, struct timeval const *now)
{
    struct mux_parser *mux_parser = DOWNCAST(parser, parser, mux_parser);
    return mux_subparser_and_parser_new(mux_parser, proto, requestor, collapse_ifaces ? &zero : &dev_id, now);
}

// cap_len is not the length of the actual packet but the size of the data we receive, ie struct frame + what we captured from the wire.
static enum proto_parse_status cap_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t unused_ cap_len, size_t unused_ wire_len, struct timeval const *now, proto_okfn_t *okfn, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct mux_parser *mux_parser = DOWNCAST(parser, parser, mux_parser);
    struct frame const *frame = (struct frame *)packet;

    // Parse
    struct cap_proto_info info;
    cap_proto_info_ctor(&info, parser, parent, frame);

    // Get an eth parser for this dev_id, or create one
    struct mux_subparser *subparser = mux_subparser_lookup(mux_parser, proto_eth, NULL, collapse_ifaces ? &zero : &frame->pkt_source->dev_id, now);

    if (! subparser) goto fallback;

    enum proto_parse_status status = proto_parse(subparser->parser, &info.info, way, frame->data, frame->cap_len, frame->wire_len, now, okfn, tot_cap_len, tot_packet);
    mux_subparser_unref(subparser);

    if (status == PROTO_OK) return PROTO_OK;

fallback:
    (void)proto_parse(NULL, &info.info, way, frame->data, frame->cap_len, frame->wire_len, now, okfn, tot_cap_len, tot_packet);
    return PROTO_OK;
}

/*
 * Proto
 */

static struct mux_proto mux_proto_cap;
struct proto *proto_cap = &mux_proto_cap.proto;

void cap_init(void)
{
    log_category_proto_capture_init();
    ext_param_collapse_ifaces_init();

    static struct proto_ops const ops = {
        .parse       = cap_parse,
        .parser_new  = mux_parser_new,
        .parser_del  = mux_parser_del,
        .info_2_str  = cap_info_2_str,
        .info_addr   = cap_info_addr,
        .serialize   = cap_serialize,
        .deserialize = cap_deserialize,
    };
    mux_proto_ctor(&mux_proto_cap, &ops, &mux_proto_ops, "Capture", PROTO_CODE_CAP, sizeof(zero)/* device_id */, 11);
}

void cap_fini(void)
{
    mux_proto_dtor(&mux_proto_cap);
    ext_param_collapse_ifaces_fini();
    log_category_proto_capture_fini();
}
