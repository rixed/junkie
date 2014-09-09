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
#include "junkie/proto/cursor.h"
#include "junkie/proto/proto.h"
#include "junkie/proto/tcp.h"
#include "junkie/proto/tds.h"
#include "junkie/proto/sql.h"
#include "junkie/proto/streambuf.h"

/* TDS has both notions of messages and packets.
 * Surely, the specifiers though that TDS will conquer TCP, UDP, Wap and the whole world,
 * so this whole packet thing, with it's length, negotiated MTU and sequence numbers,
 * was absolutely necessary.
 * Of course tody TDS runs only on top of TCP and these packet headers, according to the
 * spec itself, are unused. As a result we now have a mostly useless header possibly in the
 * way of basic messages.
 * This parser implements this useless half backed transport layer, while the
 * tds_msg parser implements the actual parsing of messages.
 *
 * Note: for greater fun, TLS start being transported by TDS (in packets of
 * pre-login types) to end up transporting TDS.
 */

#undef LOG_CAT
#define LOG_CAT proto_tds_log_category

LOG_CATEGORY_DEF(proto_tds);

struct tds_header {
    enum tds_packet_type type;
    uint8_t status;
    size_t len;
    uint16_t channel;
    uint8_t pkt_number;
    uint8_t window;
};

struct smp_header {
    uint8_t flags;
    uint16_t sid;
    uint32_t length;
    uint32_t seq_num;
    uint32_t window;
};

static char const *smp_flags_2_str(uint8_t smp_flags)
{
#define SMP_SYN 0x01
#define SMP_ACK 0x02
#define SMP_FIN 0x04
#define SMP_DATA 0x08
    return tempstr_printf("%s%s%s%s",
            smp_flags & SMP_SYN ? "SYN, " : "",
            smp_flags & SMP_ACK ? "ACK, " : "",
            smp_flags & SMP_FIN ? "FIN, " : "",
            smp_flags & SMP_DATA ? "DATA, " : "");
}

static char const *smp_header_2_str(struct smp_header *header)
{
    return tempstr_printf("Flags: %s Sid: %"PRIu16", Length: %"PRIu32", Seqnum: %"PRIu32", Window: %"PRIu32,
        smp_flags_2_str(header->flags), header->sid, header->length, header->seq_num, header->window);
}

struct tds_parser {
    struct parser parser;
    // each tds parser comes with its tds_msg parser
    struct parser *msg_parser;

    struct streambuf sbuf;
    // We give up parsing if capture has been truncated until we change way
    // However, we still advertise those packets as part of the current query
    // Keep track of tds data left if we have truncated packet
    size_t data_left;
    uint16_t channels[2];
    bool had_gap;
    uint8_t pkt_number;
    struct timeval first_ts;
};

static char const *tds_header_2_str(struct tds_header *header)
{
    return tempstr_printf("Type: %s, Status: %d, Length: %zu, Channel %"PRIu16", Pkt number %"PRIu8", Window %"PRIu8"",
        tds_packet_type_2_str(header->type), header->status, header->len, header->channel, header->pkt_number, header->window);
}

char const *tds_packet_type_2_str(enum tds_packet_type type)
{
    switch (type) {
        case TDS_PKT_TYPE_SQL_BATCH:   return "SQL batch";
        case TDS_PKT_TYPE_LOGIN:       return "Login";
        case TDS_PKT_TYPE_RPC:         return "RPC";
        case TDS_PKT_TYPE_RESULT:      return "Tabular result";
        case TDS_PKT_TYPE_ATTENTION:   return "Attention signal";
        case TDS_PKT_TYPE_BULK_LOAD:   return "Bulk load data";
        case TDS_PKT_TYPE_MANAGER_REQ: return "Transaction manager request";
        case TDS_PKT_TYPE_TDS7_LOGIN:  return "TDS7 login";
        case TDS_PKT_TYPE_SSPI:        return "SSPI";
        case TDS_PKT_TYPE_PRELOGIN:    return "Pre-login";
    }
    return tempstr_printf("Unknown TDS packet type %u", (unsigned)type);
}

static bool tds_packet_has_data(enum tds_packet_type type)
{
    switch (type) {
        case TDS_PKT_TYPE_SQL_BATCH:
        case TDS_PKT_TYPE_LOGIN:
        case TDS_PKT_TYPE_RPC:
        case TDS_PKT_TYPE_RESULT:
        case TDS_PKT_TYPE_BULK_LOAD:
        case TDS_PKT_TYPE_MANAGER_REQ:
        case TDS_PKT_TYPE_TDS7_LOGIN:
        case TDS_PKT_TYPE_SSPI:
        case TDS_PKT_TYPE_PRELOGIN:
            return true;
        case TDS_PKT_TYPE_ATTENTION:
            return false;
    }
    assert(!"Invalid tds_packet_type");
}

static parse_fun tds_sbuf_parse;

static int tds_parser_ctor(struct tds_parser *tds_parser, struct proto *proto)
{
    SLOG(LOG_DEBUG, "Constructing tds_parser@%p", tds_parser);
    assert(proto == proto_tds);
    if (0 != parser_ctor(&tds_parser->parser, proto)) return -1;
    tds_parser->msg_parser = NULL;
    tds_parser->had_gap = false;
    tds_parser->data_left = 0;
    tds_parser->channels[0] = 0;
    tds_parser->channels[1] = 0;
    tds_parser->pkt_number = 1;
    timeval_reset(&tds_parser->first_ts);
    if (0 != streambuf_ctor(&tds_parser->sbuf, tds_sbuf_parse, 30000, NULL)) {
        parser_dtor(&tds_parser->parser);
        return -1;
    }

    return 0;
}

static struct parser *tds_parser_new(struct proto *proto)
{
    struct tds_parser *tds_parser = objalloc_nice(sizeof(*tds_parser), "TDS(transp) parsers");
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
    parser_unref(&tds_parser->msg_parser);
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
 * Proto infos
 */

char const *tds_info_2_str(struct proto_info const *info_)
{
    struct tds_proto_info const *info = DOWNCAST(info_, info, tds_proto_info);
    char *str = tempstr_printf("%s, type=%s, status=0x%x, length=%"PRIu16"",
            proto_info_2_str(info_),
            tds_packet_type_2_str(info->type),
            info->status, info->length);
    return str;
}

void const *tds_info_addr(struct proto_info const *info_, size_t *size)
{
    struct tds_proto_info const *info = DOWNCAST(info_, info, tds_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

/*
 * Parse
 */

// | 1 byte      | 1 byte | 2 bytes | 4 bytes | 4 bytes | 4 bytes |
// | SMID (0x53) | Flag   | SID     | Length  | Seq num | Window  |
static enum proto_parse_status tds_parse_smp_header(struct cursor *cursor, struct smp_header *out_header)
{
#   define SMP_PKT_HDR_LEN 0x10
#   define SMP_SMID 0x53
    if (cursor_peek_u8(cursor, 0) == SMP_SMID) {
        CHECK_LEN(cursor, SMP_PKT_HDR_LEN, 0);
        cursor_drop(cursor, 1);
        out_header->flags   = cursor_read_u8(cursor);
        out_header->sid     = cursor_read_u16le(cursor);
        out_header->length  = cursor_read_u32le(cursor);
        out_header->seq_num = cursor_read_u32le(cursor);
        out_header->window  = cursor_read_u32le(cursor);
    }
    return PROTO_OK;
}

/*
 * Tds header, integers are in big-endians.
 * | 1 byte | 1 byte | 2 bytes | 2 bytes | 1 byte        | 1 byte  |
 * | Type   | Flag   | Length  | Channel | Packet number | Window  |
 */
static enum proto_parse_status tds_parse_header(struct cursor *cursor, struct tds_header *out_header, bool *unknown_token)
{
#   define TDS_PKT_HDR_LEN 8
    CHECK_LEN(cursor, TDS_PKT_HDR_LEN, 0);

    struct tds_header header;
    header.type = cursor_read_u8(cursor);
    header.status = cursor_read_u8(cursor);
    header.len = cursor_read_u16n(cursor);
    header.channel = cursor_read_u16n(cursor);
    header.pkt_number = cursor_read_u8(cursor);
    header.window = cursor_read_u8(cursor);
    SLOG(LOG_DEBUG, "Reading new TDS packet %s", tds_header_2_str(&header));

    // sanity check
    if (header.len < TDS_PKT_HDR_LEN) return PROTO_PARSE_ERR;
    switch (header.type) {
        case TDS_PKT_TYPE_SQL_BATCH:
        case TDS_PKT_TYPE_LOGIN:
        case TDS_PKT_TYPE_RPC:
        case TDS_PKT_TYPE_RESULT:
        case TDS_PKT_TYPE_ATTENTION:
        case TDS_PKT_TYPE_BULK_LOAD:
        case TDS_PKT_TYPE_MANAGER_REQ:
        case TDS_PKT_TYPE_TDS7_LOGIN:
        case TDS_PKT_TYPE_SSPI:
        case TDS_PKT_TYPE_PRELOGIN:
            break;
        default:
            SLOG(LOG_DEBUG, "Unknown tds type %u", header.type);
            if (unknown_token) *unknown_token = true;
            return PROTO_PARSE_ERR;
    }
    if (header.window != 0) {
        SLOG(LOG_DEBUG, "Window is %"PRIu8" instead of 0", header.window);
        return PROTO_PARSE_ERR;
    }
    size_t data_left = header.len - TDS_PKT_HDR_LEN;
    if ((data_left > 0) != tds_packet_has_data(header.type)) {
        SLOG(LOG_DEBUG, "This TDS packet of type %s has %zu bytes of data, but should%s have data",
                tds_packet_type_2_str(header.type), data_left, tds_packet_has_data(header.type) ? "":" not");
        return PROTO_PARSE_ERR;
    }
    if (out_header) *out_header = header;
    return PROTO_OK;
}

static enum proto_parse_status tds_sbuf_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct tds_parser *tds_parser = DOWNCAST(parser, parser, tds_parser);
    SLOG(LOG_DEBUG, "Got tds packet, data_left %zu, way %d", tds_parser->data_left, way);
    bool has_gap = wire_len > cap_len;

    if (tds_parser->had_gap && tds_parser->data_left > 0) {
        tds_parser->data_left = wire_len > tds_parser->data_left ? 0 : tds_parser->data_left - wire_len;
        SLOG(LOG_DEBUG, "Discard tds with gap, data_left %zu...", tds_parser->data_left);
        timeval_reset(&tds_parser->first_ts);
        return PROTO_OK;
    }
    tds_parser->had_gap = has_gap;

    struct tds_header tds_header;
    bool unknown_token = false;
    struct cursor cursor;
    enum proto_parse_status status;
    cursor_ctor(&cursor, payload, cap_len);

    struct smp_header smp_header = {.length = 0};
    if (PROTO_OK != (status = tds_parse_smp_header(&cursor, &smp_header))) return status;
    if (smp_header.length) {
        SLOG(LOG_DEBUG, "Smp header: %s", smp_header_2_str(&smp_header));
        wire_len -= SMP_PKT_HDR_LEN;
        cap_len -= SMP_PKT_HDR_LEN;
        if (smp_header.flags & SMP_ACK) return PROTO_OK;
    }

    status = tds_parse_header(&cursor, &tds_header, &unknown_token);
    if (status != PROTO_OK) {
        // We have an unknown token if the payload is encrypted after a ssl handshake
        // It is valid but we don't know how to parse it yet
        // TODO It would be better if we knew the values of the encryption options exchanged in prelogin messages
        timeval_reset(&tds_parser->first_ts);
        if (unknown_token) return PROTO_OK;
        return status;
    }

    // Sanity check on pkt number
    if (tds_header.pkt_number > 1 && ((tds_parser->pkt_number + 1) != tds_header.pkt_number)) {
        SLOG(LOG_DEBUG, "Expected pkt number %"PRIu8", got %"PRIu8"",
                tds_parser->pkt_number + 1, tds_header.pkt_number);
        tds_parser->pkt_number = 1;
        timeval_reset(&tds_parser->first_ts);
        return PROTO_PARSE_ERR;
    } else if (tds_header.pkt_number <= 1) {
        SLOG(LOG_DEBUG, "Reset pkt number from %"PRIu8"", tds_parser->pkt_number);
        tds_parser->pkt_number = 1;
    }

    // Sanity check on channels
    if (tds_parser->channels[way] && (tds_parser->channels[way] != tds_header.channel)) {
        SLOG(LOG_DEBUG, "Expected channel %"PRIu16", got channel %"PRIu16"",
                tds_parser->channels[way], tds_header.channel);
        timeval_reset(&tds_parser->first_ts);
        return PROTO_PARSE_ERR;
    }

    if (wire_len > tds_header.len) {
        SLOG(LOG_DEBUG, "Wire len %zu unexpected (> %zu), considering a gap", wire_len, tds_header.len);
        has_gap = true;
    }
    tds_parser->data_left = wire_len >= tds_header.len ? 0 : tds_header.len - wire_len;
    SLOG(LOG_DEBUG, "Data left after wire %zu", tds_parser->data_left);
    if (tds_parser->data_left > 0 && !has_gap) {
        SLOG(LOG_DEBUG, "Incomplete tds packet, buffering it");
        if (!timeval_is_set(&tds_parser->first_ts)) {
            SLOG(LOG_DEBUG, "Setting first ts to %s for way %d", timeval_2_str(now), way);
            tds_parser->first_ts = *now;
        }
        proto_parse(NULL, parent, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
        streambuf_set_restart(&tds_parser->sbuf, way, payload, tds_header.len);
        return PROTO_OK;
    }

    // We have a buffered tds packet at this point
    if (!timeval_is_set(&tds_parser->first_ts)) {
        SLOG(LOG_DEBUG, "Setting first ts to %s for way %d since it is not setted", timeval_2_str(now), way);
        tds_parser->first_ts = *now;
    }

    struct tds_proto_info info;
    proto_info_ctor(&info.info, parser, parent, TDS_PKT_HDR_LEN, tds_header.len - TDS_PKT_HDR_LEN);
    info.type = tds_header.type;
    info.status = tds_header.status;
    info.length = tds_header.len;
    info.first_ts = tds_parser->first_ts;
    info.has_gap = has_gap;
    if (tds_header.channel > 0) {
        SLOG(LOG_DEBUG, "Saving channel %"PRIu16"", tds_header.channel);
        tds_parser->channels[way] = tds_header.channel;
    }
    SLOG(LOG_DEBUG, "Saving pkt number %"PRIu8"", tds_header.pkt_number);
    tds_parser->pkt_number = tds_header.pkt_number;

    SLOG(LOG_DEBUG, "Parsing %s", tds_header_2_str(&tds_header));
    if (! tds_parser->msg_parser) {
        SLOG(LOG_DEBUG, "Building new tds_msg_parser");
        tds_parser->msg_parser = proto_tds_msg->ops->parser_new(proto_tds_msg);
        if (!tds_parser->msg_parser) {
            SLOG(LOG_INFO, "Could not build tds msg parser");
            return PROTO_PARSE_ERR;
        }
    }
    if (tds_header.status & TDS_EOM) {
        SLOG(LOG_DEBUG, "Reset pkt number from %"PRIu8" since we parsed an EOM", tds_parser->pkt_number);
        tds_parser->pkt_number = 1;
    }
    status = proto_parse(tds_parser->msg_parser, &info.info, way,
            cursor.head, cursor.cap_len, wire_len - TDS_PKT_HDR_LEN, now, tot_cap_len, tot_packet);
    if (status != PROTO_OK) {
        SLOG(LOG_INFO, "Tds msg parse failed, returning %s", proto_parse_status_2_str(status));
        return status;
    }
    timeval_reset(&tds_parser->first_ts);
    // Advertise this packet if it was not done already
    return proto_parse(NULL, &info.info, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);
}

static enum proto_parse_status tds_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct tds_parser *tds_parser = DOWNCAST(parser, parser, tds_parser);

    if (cap_len == 0 && wire_len > 0) return PROTO_TOO_SHORT;   // We do not know how to handle pure gaps
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
        .info_2_str  = tds_info_2_str,
        .info_addr   = tds_info_addr
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

