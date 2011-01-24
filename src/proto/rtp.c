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
#include <arpa/inet.h>
#include <inttypes.h>
#include <junkie/tools/tempstr.h>
#include <junkie/proto/proto.h>
#include <junkie/proto/rtp.h>

static char const Id[] = "$Id: 7730ab99426100f6032d4a006fe59b9a5c492958 $";

#undef LOG_CAT
#define LOG_CAT proto_rtp_log_category

LOG_CATEGORY_DEF(proto_rtp);

struct rtp_hdr {
    uint8_t flags0, flags1;
#   define F0_CSRC_COUNT_MASK 0x0FU
#   define F0_EXTENSION_MASK  0x10U // presence of a header extension
#   define F0_PADDING_MASK    0x20U // presence of padding at the end of payload
#   define F0_VERSION_MASK    0xC0U // should be 2
#   define F1_MARKER_MASK     0x80U
#   define F1_PLD_TYPE_MASK   0x7FU
    uint16_t seq_num;
    uint32_t timestamp;
    uint32_t ssrc;
    uint32_t csrc[];
};

/*
 * Proto infos
 */

char const *rtp_payload_type_2_str(uint8_t type)
{
    static char const *strs[] = {
        "PCMU", "reserved", "reserved", "GSM", "G723", "DVI4/8k", "DVI4/16k", "LPC",
        "PCMA", "G722", "L16/2chan", "L16/mono", "QCELP", "CN", "MPA", "G728",
        "DVI4/11k", "DVI4/22k", "G729", "reserved", "unassigned", "unassigned", "unassigned", "unassigned",
        "unasigned", "CelB", "JPEG", "unassigned", "nv", "unassigned", "unassigned", "H261",
        "MPV", "MP2T", "H263"
    };
    if (type < NB_ELEMS(strs)) return strs[type];
    else if (type >= 35 && type <= 71) return "unasigned";
    else if (type >= 72 && type <= 76) return "reserved";
    else if (type >= 77 && type <= 95) return "unassigned";
    else if (type >= 96 && type <= 127) return "dynamic";
    return "invalid";
}

static void const *rtp_info_addr(struct proto_info const *info_, size_t *size)
{
    struct rtp_proto_info const *info = DOWNCAST(info_, info, rtp_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *rtp_info_2_str(struct proto_info const *info_)
{
    struct rtp_proto_info const *info = DOWNCAST(info_, info, rtp_proto_info);
    char *str = tempstr();

    snprintf(str, TEMPSTR_SIZE, "%s, payload_type=%s, SSRC=%"PRIu32", seqnum=%"PRIu16", timestamp=%"PRIu32,
        proto_info_2_str(info_), rtp_payload_type_2_str(info->payload_type), info->sync_src, info->seq_num, info->timestamp);

    return str;
}

static void rtp_proto_info_ctor(struct rtp_proto_info *info, struct parser *parser, struct proto_info *parent, struct rtp_hdr const *rtph, size_t head_len, size_t payload)
{
    proto_info_ctor(&info->info, parser, parent, head_len, payload);
    info->payload_type = READ_U8(&rtph->flags1) & F1_PLD_TYPE_MASK;
    info->sync_src = READ_U32N(&rtph->ssrc);
    info->seq_num = READ_U16N(&rtph->seq_num);
    info->timestamp = READ_U32N(&rtph->timestamp);
}

/*
 * Parse
 * Note: We assume RTP/AVP profile
 */

static enum proto_parse_status rtp_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn, size_t tot_cap_len, uint8_t const *tot_packet)
{
    SLOG(LOG_DEBUG, "Starting RTP analysis");

    /* Parse */
    struct rtp_hdr *rtph = (struct rtp_hdr *)packet;
    if (wire_len < sizeof(*rtph)) return PROTO_PARSE_ERR;
    if (cap_len < sizeof(*rtph)) return PROTO_TOO_SHORT;

    unsigned const version = READ_U8(&rtph->flags0) >> 6U;
    unsigned const csrc_count = READ_U8(&rtph->flags0) & F0_CSRC_COUNT_MASK;
    unsigned const payload_type = READ_U8(&rtph->flags1) & F1_PLD_TYPE_MASK;
    SLOG(LOG_DEBUG, "RTP header, version=%u, CSRC_count=%u, payload_type=%u", version, csrc_count, payload_type);

    size_t head_len = sizeof(*rtph) + csrc_count * 4;
    if (wire_len < head_len) return PROTO_PARSE_ERR;
    if (cap_len < head_len) return PROTO_TOO_SHORT;

    struct rtp_proto_info info;
    rtp_proto_info_ctor(&info, parser, parent, rtph, head_len, wire_len - head_len);

    return proto_parse(NULL, &info.info, way, NULL, 0, 0, now, okfn, tot_cap_len, tot_packet);
}

/*
 * Init
 */

static struct uniq_proto uniq_proto_rtp;
struct proto *proto_rtp = &uniq_proto_rtp.proto;

void rtp_init(void)
{
    log_category_proto_rtp_init();

    static struct proto_ops const ops = {
        .parse      = rtp_parse,
        .parser_new = uniq_parser_new,
        .parser_del = uniq_parser_del,
        .info_2_str = rtp_info_2_str,
        .info_addr  = rtp_info_addr,
    };
    uniq_proto_ctor(&uniq_proto_rtp, &ops, "RTP");
}

void rtp_fini(void)
{
    uniq_proto_dtor(&uniq_proto_rtp);
    log_category_proto_rtp_fini();
}
