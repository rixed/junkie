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
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <arpa/inet.h>
#include "junkie/cpp.h"
#include "junkie/tools/tempstr.h"
#include "junkie/proto/rtcp.h"

#undef LOG_CAT
#define LOG_CAT proto_rtcp_log_category

LOG_CATEGORY_DEF(proto_rtcp);

struct rtcp_hdr {
    uint8_t flags;
#   define REC_COUNT_MASK 0x1FU
#   define PADDING_MASK   0x20U
#   define VERSION_MASK   0xC0U
    uint8_t type;
    uint16_t length;
    uint32_t ssrc;
    // for sender report, then follow the sender info
    struct rtcp_sender_info {
        uint32_t ntp_ts_msw, ntp_ts_lsw;
        uint32_t rtp_ts;
        uint32_t packet_count, octet_count;
    } packed_ info[];
} packed_;

struct rtcp_report_bloc {
    uint32_t ssrc;
    uint8_t fraction_lost;
    uint8_t tot_lost[3];
    uint32_t highest_seqnum;
    uint32_t inter_jitter;
    uint32_t last_sr;
    uint32_t delay_since_last_sr;
} packed_;

/*
 * Proto infos
 */

static void const *rtcp_info_addr(struct proto_info const *info_, size_t *size)
{
    struct rtcp_proto_info const *info = DOWNCAST(info_, info, rtcp_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *rtcp_info_2_str(struct proto_info const *info_)
{
    struct rtcp_proto_info const *info = DOWNCAST(info_, info, rtcp_proto_info);
    char *str = tempstr();

    snprintf(str, TEMPSTR_SIZE, "%s, cumul_lost=%"PRId32", jitter=%"PRIu32", lsr=0x%"PRIx32", dlsr=%"PRIu32", ntp=0x%"PRIx32,
        proto_info_2_str(info_),
        info->cumul_lost, info->jitter, info->lsr, info->dlsr, info->ntp_ts);

    return str;
}

static void rtcp_proto_info_ctor(struct rtcp_proto_info *info, struct parser *parser, struct proto_info *parent, size_t head_len, size_t payload, int32_t packet_lost, uint32_t jitter, uint32_t lst, uint32_t dlsr, uint32_t ntp_ts)
{
    proto_info_ctor(&info->info, parser, parent, head_len, payload);
    info->cumul_lost = packet_lost;
    info->jitter = jitter;
    info->lsr = lst;
    info->dlsr = dlsr;
    info->ntp_ts = ntp_ts;
}

/*
 * Parse
 */

static enum proto_parse_status rtcp_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct rtcp_hdr const *rtcphd = (struct rtcp_hdr *)packet;

    // Sanity Check
    if (wire_len < sizeof(*rtcphd)) return PROTO_PARSE_ERR;
    if (cap_len < sizeof(*rtcphd)) return PROTO_TOO_SHORT;

    size_t len = (READ_U16N(&rtcphd->length) + 1) * 4;
    if (wire_len < len) return PROTO_PARSE_ERR;
    if (cap_len < len) return PROTO_TOO_SHORT;

    // Parse
    unsigned const version = READ_U8(&rtcphd->flags) >> 6U;
    unsigned const rec_count = READ_U8(&rtcphd->flags) & REC_COUNT_MASK;
    unsigned const type = READ_U8(&rtcphd->type);
    SLOG(LOG_DEBUG, "version=%u, rec_count=%u", version, rec_count);
    if (rec_count == 0) {
        SLOG(LOG_DEBUG, "Giving up since no record");
giveup:
        return proto_parse(NULL, parent, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
    }

    int32_t packet_lost = 0;
    uint32_t jitter = 0, lsr = 0, dlsr = 0, ntp_ts = 0;
    struct rtcp_report_bloc const *report;
    switch (type) {
        case 200:   // Sender report -> we have a rtcp_sender_info
            report = (struct rtcp_report_bloc *)(rtcphd->info+1);
            if ((ssize_t)len < (uint8_t *)report - packet) return PROTO_PARSE_ERR;    // check we have at least sender info block
            ntp_ts = ((READ_U32N(&rtcphd->info[0].ntp_ts_msw) & 0x0000ffffU) << 16) | ((READ_U32N(&rtcphd->info[0].ntp_ts_lsw) & 0xffff0000U) >> 16);
            break;
        case 201:   // Receiver report -> we have no rtcp_sender_info
            report = (struct rtcp_report_bloc *)rtcphd->info;
            break;
        default:
            goto giveup;
    }

    if ((ssize_t)len >= (uint8_t *)(report + 1) - packet) {
        packet_lost = READ_U24N(report->tot_lost);
        jitter = READ_U32N(&report->inter_jitter);
        lsr = READ_U32N(&report->last_sr);
        dlsr = READ_U32N(&report->delay_since_last_sr);
    } // FIXME: else jitter, packet_lost, lsr and ntp_ts are not set ?

    struct rtcp_proto_info info;
    rtcp_proto_info_ctor(&info, parser, parent, wire_len, 0, packet_lost, jitter, lsr, dlsr, ntp_ts);

    return proto_parse(NULL, &info.info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
}

/*
 * Init
 */

static struct uniq_proto uniq_proto_rtcp;
struct proto *proto_rtcp = &uniq_proto_rtcp.proto;


void rtcp_init(void)
{
    log_category_proto_rtcp_init();

    static struct proto_ops const ops = {
        .parse       = rtcp_parse,
        .parser_new  = uniq_parser_new,
        .parser_del  = uniq_parser_del,
        .info_2_str  = rtcp_info_2_str,
        .info_addr   = rtcp_info_addr
    };

    uniq_proto_ctor(&uniq_proto_rtcp, &ops, "RTCP", PROTO_CODE_RTCP);
}

void rtcp_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    uniq_proto_dtor(&uniq_proto_rtcp);
#   endif
    log_category_proto_rtcp_fini();
}
