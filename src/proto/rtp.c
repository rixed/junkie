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

LOG_CATEGORY_DEC(proto_rtp);
LOG_CATEGORY_DEF(proto_rtp);

struct rtp_header {
#   ifndef WORDS_BIGENDIAN
    uint8_t csrc_count:4;
    uint8_t extension:1;
    uint8_t padding:1;
    uint8_t version:2;
    uint8_t payload_type:7;
    uint8_t marker:1;
#   else
    uint8_t version:2;  // should be 2
    uint8_t padding:1;  // presence of padding at the end of payload
    uint8_t extension:1;    // presence of a header extension
    uint8_t csrc_count:4;
    uint8_t marker:1;
    uint8_t payload_type:7;
#   endif
    uint16_t seq_num;
    uint32_t timestamp;
    uint32_t ssrc;
    uint32_t csrc[];
};

/*
 * Proto infos
 */

static char const *rtp_info_2_str(struct proto_info const *info_)
{
    struct rtp_proto_info const *info = DOWNCAST(info_, info, rtp_proto_info);
    char *str = tempstr();

    snprintf(str, TEMPSTR_SIZE, "%s, payload_type=%"PRIu8", SSRC=%"PRIu32", seqnum=%"PRIu16", timestamp=%"PRIu32,
        proto_info_2_str(info_), info->payload_type, info->sync_src, info->seq_num, info->timestamp);

    return str;
}

static void rtp_proto_info_ctor(struct rtp_proto_info *info, struct parser *parser, struct proto_info const *parent, struct rtp_header const *rtph, size_t head_len, size_t payload)
{
    proto_info_ctor(&info->info, parser, parent, head_len, payload);
    info->payload_type = rtph->payload_type;
    info->sync_src = ntohl(rtph->ssrc);
    info->seq_num = ntohs(rtph->seq_num);
    info->timestamp = ntohl(rtph->timestamp);
}

/*
 * Parse
 * Note: We assume RTP/AVP profile
 */

static enum proto_parse_status rtp_parse(struct parser *parser, struct proto_info const *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn)
{
    SLOG(LOG_DEBUG, "Starting RTP analysis");

    /* Parse */
    struct rtp_header *rtph = (struct rtp_header *)packet;
    if (wire_len < sizeof(*rtph)) return PROTO_PARSE_ERR;
    if (cap_len < sizeof(*rtph)) return PROTO_TOO_SHORT;

    SLOG(LOG_DEBUG, "RTP header, version=%u, CSRC_count=%u, payload_type=%u",
        rtph->version, rtph->csrc_count, rtph->payload_type);

    size_t head_len = sizeof(*rtph) + rtph->csrc_count * 4;
    if (wire_len < head_len) return PROTO_PARSE_ERR;
    if (cap_len < head_len) return PROTO_TOO_SHORT;

    struct rtp_proto_info info;
    rtp_proto_info_ctor(&info, parser, parent, rtph, head_len, wire_len - head_len);

    return proto_parse(NULL, &info.info, way, NULL, 0, 0, now, okfn);
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
    };
    uniq_proto_ctor(&uniq_proto_rtp, &ops, "RTP");
}

void rtp_fini(void)
{
    uniq_proto_dtor(&uniq_proto_rtp);
    log_category_proto_rtp_fini();
}
