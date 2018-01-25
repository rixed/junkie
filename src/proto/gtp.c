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
#include "junkie/proto/cursor.h"
#include "junkie/proto/ip.h"
#include "junkie/proto/udp.h"
#include "junkie/proto/gtp.h"

#undef LOG_CAT
#define LOG_CAT proto_gtp_log_category

LOG_CATEGORY_DEF(proto_gtp);

#define GTP_HASH_SIZE 67

/*
 * proto_info
 */

static void const *gtp_info_addr(struct proto_info const *info_, size_t *size)
{
    struct gtp_proto_info const *info = DOWNCAST(info_, info, gtp_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *msg_type_2_str(enum gtp_msg_type t)
{
    switch (t) {
        case GTP_ECHO_REQ: return "ECHO REQUEST";
        case GTP_ECHO_RESP: return "ECHO RESPONSE";
        case GTP_VERSION_NOT_SUPPORTED: return "VERSION NOT SUPPORTED";
        case GTP_NODE_ALIVE_REQ: return "NODE ALIVE REQUEST";
        case GTP_NODE_ALIVE_RESP: return "NODE ALIVE RESPONSE";
        case GTP_REDIRECTION_REQ: return "REDIRECTION REQUEST";
        case GTP_REDIRECTION_RESP: return "REDIRECTION RESPONSE";
        case GTP_CREATE_PDP_CONTEXT_REQ: return "CREATE PDP CONTEXT REQUEST";
        case GTP_CREATE_PDP_CONTEXT_RESP: return "CREATE PDP CONTEXT RESPONSE";
        case GTP_UPDATE_PDP_CONTEXT_REQ: return "UPDATE PDP CONTEXT REQUEST";
        case GTP_UPDATE_PDP_CONTEXT_RESP: return "UPDATE PDP CONTEXT RESPONSE";
        case GTP_DELETE_PDP_CONTEXT_REQ: return "DELETE PDP CONTEXT REQUEST";
        case GTP_DELETE_PDP_CONTEXT_RESP: return "DELETE PDP CONTEXT RESPONSE";
        case GTP_INITIATE_PDP_CONTEXT_ACTIV_REQ: return "INITIATE PDP CONTEXT ACTIV REQUEST";
        case GTP_INITIATE_PDP_CONTEXT_ACTIV_RESP: return "INITIATE PDP CONTEXT ACTIV RESPONSE";
        case GTP_ERROR_INDIC: return "ERROR INDIC";
        case GTP_PDU_NOTIF_REQ: return "PDU NOTIF REQUEST";
        case GTP_PDU_NOTIF_RESP: return "PDU NOTIF RESPONSE";
        case GTP_PDU_NOTIF_REJECT_REQ: return "PDU NOTIF REJECT REQUEST";
        case GTP_PDU_NOTIF_REJECT_RESP: return "PDU NOTIF REJECT RESPONSE";
        case GTP_SUPPORTED_EXTENSIONS_NOTIF: return "SUPPORTED EXTENSIONS NOTIF";
        case GTP_SEND_ROUTING_INFO_REQ: return "SEND ROUTING INFO REQUEST";
        case GTP_SEND_ROUTING_INFO_RESP: return "SEND ROUTING INFO RESPONSE";
        case GTP_FAILURE_REPORT_REQ: return "FAILURE REPORT REQUEST";
        case GTP_FAILURE_REPORT_RESP: return "FAILURE REPORT RESPONSE";
        case GTP_MS_PRESENT_REQ: return "MS PRESENT REQUEST";
        case GTP_MS_PRESENT_RESP: return "MS PRESENT RESPONSE";
        case GTP_IDENTIFICATION_REQ: return "IDENTIFICATION REQUEST";
        case GTP_IDENTIFICATION_RESP: return "IDENTIFICATION RESPONSE";
        case GTP_SGSN_CONTEXT_REQ: return "SGSN CONTEXT REQUEST";
        case GTP_SGSN_CONTEXT_RESP: return "SGSN CONTEXT RESPONSE";
        case GTP_SGSN_CONTEXT_ACK: return "SGSN CONTEXT ACK";
        case GTP_FORWARD_RELOC_REQ: return "FORWARD RELOC REQUEST";
        case GTP_FORWARD_RELOC_RESP: return "FORWARD RELOC RESPONSE";
        case GTP_FORWARD_RELOC_COMPLETE: return "FORWARD RELOC COMPLETE";
        case GTP_RELOC_CANCEL_REQ: return "RELOC CANCEL REQUEST";
        case GTP_RELOC_CANCEL_RESP: return "RELOC CANCEL RESPONSE";
        case GTP_FORWARD_SRNS_CONTEXT: return "FORWARD SRNS CONTEXT";
        case GTP_FORWARD_RELOC_COMPLETE_ACK: return "FORWARD RELOC COMPLETE ACK";
        case GTP_FORWARD_SRNS_CONTEXT_ACK: return "FORWARD SRNS CONTEXT ACK";
        case GTP_UE_REGISTRATION_QUERY_REQ: return "UE REGISTRATION QUERY REQUEST";
        case GTP_UE_REGISTRATION_QUERY_RESP: return "UE REGISTRATION QUERY RESPONSE";
        case GTP_RAN_INFO_RELAY: return "RAN INFO RELAY";
        case GTP_MBMS_NOTIF_REQ: return "MBMS NOTIF REQUEST";
        case GTP_MBMS_NOTIF_RESP: return "MBMS NOTIF RESPONSE";
        case GTP_MBMS_NOTIF_REJECT_REQ: return "MBMS NOTIF REJECT REQUEST";
        case GTP_MBMS_NOTIF_REJECT_RESP: return "MBMS NOTIF REJECT RESPONSE";
        case GTP_CREATE_MBMS_CONTEXT_REQ: return "CREATE MBMS CONTEXT REQUEST";
        case GTP_CREATE_MBMS_CONTEXT_RESP: return "CREATE MBMS CONTEXT RESPONSE";
        case GTP_UPDATE_MBMS_CONTEXT_REQ: return "UPDATE MBMS CONTEXT REQUEST";
        case GTP_UPDATE_MBMS_CONTEXT_RESP: return "UPDATE MBMS CONTEXT RESPONSE";
        case GTP_DELETE_MBMS_CONTEXT_REQ: return "DELETE MBMS CONTEXT REQUEST";
        case GTP_DELETE_MBMS_CONTEXT_RESP: return "DELETE MBMS CONTEXT RESPONSE";
        case GTP_MBMS_REGISTRATION_REQ: return "MBMS REGISTRATION REQUEST";
        case GTP_MBMS_REGISTRATION_RESP: return "MBMS REGISTRATION RESPONSE";
        case GTP_MBMS_DEREGISTRATION_REQ: return "MBMS DEREGISTRATION REQUEST";
        case GTP_MBMS_DEREGISTRATION_RESP: return "MBMS DEREGISTRATION RESPONSE";
        case GTP_MBMS_SESSION_START_REQ: return "MBMS SESSION START REQUEST";
        case GTP_MBMS_SESSION_START_RESP: return "MBMS SESSION START RESPONSE";
        case GTP_MBMS_SESSION_STOP_REQ: return "MBMS SESSION STOP REQUEST";
        case GTP_MBMS_SESSION_STOP_RESP: return "MBMS SESSION STOP RESPONSE";
        case GTP_MBMS_SESSION_UPDATE_REQ: return "MBMS SESSION UPDATE REQUEST";
        case GTP_MBMS_SESSION_UPDATE_RESP: return "MBMS SESSION UPDATE RESPONSE";
        case GTP_MS_INFO_CHG_NOTIF_REQ: return "MS INFO CHG NOTIF REQUEST";
        case GTP_MS_INFO_CHG_NOTIF_RESP: return "MS INFO CHG NOTIF RESPONSE";
        case GTP_DATA_RECORD_TRANSFERT_REQ: return "DATA RECORD TRANSFERT REQUEST";
        case GTP_DATA_RECORD_TRANSFERT_RESP: return "DATA RECORD TRANSFERT RESPONSE";
        case GTP_END_MARKER: return "END MARKER";
        case GTP_GPDU: return "G-PDU";
        default: return tempstr_printf("Unknown GTP message type %d", t);
    }
}

static char const *gtp_info_2_str(struct proto_info const *info_)
{
    struct gtp_proto_info const unused_ *info = DOWNCAST(info_, info, gtp_proto_info);
    return tempstr_printf("%s, Version:%u, MsgType:%s%s%s%s",
        proto_info_2_str(info_),
        info->version,
        msg_type_2_str(info->msg_type),
        info->set_values & GTP_HAS_TEID ? tempstr_printf(", TEID:%"PRIu32, info->teid) : "",
        info->set_values & GTP_HAS_SEQNUM ? tempstr_printf(", SeqNum:%"PRIu16, info->seqnum) : "",
        info->set_values & GTP_HAS_NPDU_NUMBER ? tempstr_printf(", N-PDU:%"PRIu8, info->npdu_number) : "");
}

static void gtp_proto_info_ctor(struct gtp_proto_info *info, struct parser *parser, struct proto_info *parent, size_t head_len, size_t payload)
{
    proto_info_ctor(&info->info, parser, parent, head_len, payload);
    info->set_values = 0;
}

/*
 * Parse
 */

static enum proto_parse_status parse_gpdu(struct mux_parser *mux_parser, struct gtp_proto_info *info, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    /* We will ignore the seqnum and not reorder the packets, regardless
     * of the Reordering Required flag of the PDP context; PDP context
     * that we ignore as well.
     *
     * Nothing tells us what protocol is being transported.
     * Let's assume IPv4. */

    // Search our IP subparser for this TEID
    struct mux_subparser *subparser = mux_subparser_lookup(mux_parser, proto_ip, proto_gtp, &info->teid, now);

    enum proto_parse_status status = proto_parse(subparser->parser, &info->info, way, packet, cap_len, wire_len, now, tot_cap_len, tot_packet);

    if (subparser) mux_subparser_unref(&subparser);
    if (status == PROTO_OK) return status;

    return proto_parse(NULL, &info->info, way, packet, cap_len, wire_len, now, tot_cap_len, tot_packet);
}

static enum proto_parse_status parse_version1(struct mux_parser *mux_parser, struct gtp_proto_info *info, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct cursor cur;
    cursor_ctor(&cur, packet, cap_len);
#   define CHECK(n) CHECK_LEN(&cur, n, 0)
    CHECK(8);

    uint8_t flags = cursor_read_u8(&cur);

    // We do not care about GTP':
    if (!(flags & 0x10)) {
        SLOG(LOG_DEBUG, "GTP', bailing out");
        return PROTO_PARSE_ERR;
    }

    bool has_extension = flags & 0x04;
    info->set_values |= GTP_HAS_TEID |
                        (flags & 0x02 ? GTP_HAS_SEQNUM : 0) |
                        (flags & 0x01 ? GTP_HAS_NPDU_NUMBER : 0);
    info->msg_type = cursor_read_u8(&cur);
    size_t msg_length = cursor_read_u16n(&cur);
    info->teid = cursor_read_u32n(&cur);
    // After that starts the message which length is msg_length
    uint8_t const *msg_start = cur.head;

    enum gtp_extension_type {
        GTP_EXT_NO_MORE = 0x00,
        GTP_EXT_MBMS_SUPPORT_INDIC = 0x01,
        GTP_EXT_MSINFO_CHG_REP_SUPPORT_INDIC = 0x02,
        // TODO: Check 3GPP TS 29.281 [41]
        GTP_EXT_PDCT_PDU_NUMBER = 0xC0,
        GTP_EXT_SUSPEND_REQ = 0xC1,
        GTP_EXT_SUSPEND_RESP = 0xC2,
    } next_header_type = GTP_EXT_NO_MORE;

    if (flags & 7) {
        CHECK(4);
        info->seqnum = info->set_values & GTP_HAS_SEQNUM ?
            cursor_read_u16n(&cur) : 0;
        info->npdu_number = info->set_values & GTP_HAS_NPDU_NUMBER ?
            cursor_read_u8(&cur) : 0;
        next_header_type = has_extension ? cursor_read_u8(&cur) : 0;
    }

    // Skip headers
    while (next_header_type != GTP_EXT_NO_MORE) {
        CHECK(4);
        size_t len = *cur.head << 2U;
        CHECK(len);
        next_header_type = cur.head[len-1];
        cursor_drop(&cur, len);
    }

    msg_length -= cur.head - msg_start;

    switch (info->msg_type) {
        case GTP_GPDU:
            wire_len -= cur.head - packet;
            if (msg_length != wire_len) {
                SLOG(LOG_DEBUG, "GPDU msg length (%zu) != wire length (%zu)",
                        msg_length, wire_len);
            }
            return parse_gpdu(mux_parser, info, way, cur.head, cur.cap_len, wire_len, now, tot_cap_len, tot_packet);
        default:
            return proto_parse(NULL, &info->info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
    }
}

static enum proto_parse_status parse_version2(struct mux_parser unused_ *mux_parser, struct gtp_proto_info *info, unsigned way, uint8_t const unused_ *packet, size_t unused_ cap_len, size_t unused_ wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    return proto_parse(NULL, &info->info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
}

static enum proto_parse_status gtp_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct mux_parser *mux_parser = DOWNCAST(parser, parser, mux_parser);

    SLOG(LOG_DEBUG, "GTP with wire_len = %zu and cap_len = %zu", wire_len, cap_len);
    // GTP v1 or v2 are at least 64bits:
    if (wire_len < 8) return PROTO_PARSE_ERR;
    if (cap_len < 8) return PROTO_TOO_SHORT;

    struct gtp_proto_info info;
    gtp_proto_info_ctor(&info, parser, parent, 0, wire_len);
    info.version = packet[0] >> 5;

    switch (info.version) {
        case 1:
            return parse_version1(mux_parser, &info, way, packet, cap_len, wire_len, now, tot_cap_len, tot_packet);
        case 2:
            return parse_version2(mux_parser, &info, way, packet, cap_len, wire_len, now, tot_cap_len, tot_packet);
        default:
            SLOG(LOG_DEBUG, "Unknown version %d", info.version);
            return PROTO_PARSE_ERR;
    }
}

/*
 * Init
 */

static struct mux_proto mux_proto_gtp;
struct proto *proto_gtp = &mux_proto_gtp.proto;
static struct port_muxer udp_port_muxer_userdata;  // GTP-u
static struct port_muxer udp_port_muxer_control;   // GTP-c

void gtp_init(void)
{
    log_category_proto_gtp_init();

    static struct proto_ops const ops = {
        .parse       = gtp_parse,
        .parser_new  = mux_parser_new,
        .parser_del  = mux_parser_del,
        .info_2_str  = gtp_info_2_str,
        .info_addr   = gtp_info_addr
    };
    mux_proto_ctor(&mux_proto_gtp, &ops, &mux_proto_ops, "GTP", PROTO_CODE_GTP, sizeof(uint32_t), GTP_HASH_SIZE);
    port_muxer_ctor(&udp_port_muxer_userdata, &udp_port_muxers, 2152, 2152, proto_gtp); // GTP-U
    port_muxer_ctor(&udp_port_muxer_control, &udp_port_muxers, 2123, 2123, proto_gtp);  // GTP-C
}

void gtp_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    port_muxer_dtor(&udp_port_muxer_userdata, &udp_port_muxers);
    port_muxer_dtor(&udp_port_muxer_control, &udp_port_muxers);
    mux_proto_dtor(&mux_proto_gtp);
#   endif
    log_category_proto_gtp_fini();
}
