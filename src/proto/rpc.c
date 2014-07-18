// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2014, SecurActive.
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

#include "junkie/proto/rpc.h"
#include "junkie/proto/cursor.h"
#include "junkie/proto/tcp.h"
#include "junkie/proto/udp.h"

#undef LOG_CAT
#define LOG_CAT proto_rpc_log_category

LOG_CATEGORY_DEF(proto_rpc);

static char const *msg_type_2_str(enum msg_type msg_type)
{
    switch (msg_type) {
        case RPC_CALL: return "CALL";
        case RPC_REPLY: return "REPLY";
        default: return tempstr_printf("unknown (%"PRIu32")", msg_type);
    }
}

static char const *reply_status_2_str(enum reply_status reply_status)
{
    switch (reply_status) {
        case RPC_MSG_ACCEPTED: return "MSG_ACCEPTED";
        case RPC_MSG_DENIED: return "MSG_DENIED";
        default: return tempstr_printf("unknown (%"PRIu32")", reply_status);
    }
}

static char const *call_msg_2_str(struct call_msg const *call_msg)
{
    return tempstr_printf("rpc version: %"PRIu32", program: %"PRIu32", program version: %"PRIu32", procedure: %"PRIu32,
            call_msg->rpc_version, call_msg->program, call_msg->program_version, call_msg->procedure);
}

static char const *reply_msg_2_str(struct reply_msg const *reply_msg)
{
    return tempstr_printf("reply status : %s", reply_status_2_str(reply_msg->reply_status));
}

char const *rpc_info_2_str(struct proto_info const *info_)
{
    struct rpc_proto_info const *info = DOWNCAST(info_, info, rpc_proto_info);
    return tempstr_printf("type: %s, %s", msg_type_2_str(info->msg_type),
            info->msg_type == RPC_CALL ? call_msg_2_str(&info->u.call_msg) : reply_msg_2_str(&info->u.reply_msg) );
}

#define RPC_CHECK_AUTH(VAR) \
    enum auth_flavor VAR = cursor_read_u32n(cursor); \
    if (VAR > RPC_AUTH_DES) { \
        SLOG(LOG_DEBUG, "Invalid VAR auth flavor (got %"PRIu32")", VAR); \
        return PROTO_PARSE_ERR; \
    } \
    uint32_t VAR##_length = cursor_read_u32n(cursor); \
    CHECK(VAR##_length); \
    cursor_drop(cursor, VAR##_length);

static enum proto_parse_status parse_rpc_call(struct cursor *cursor, struct rpc_proto_info *info)
{
    info->u.call_msg.rpc_version = cursor_read_u32n(cursor);
    if (info->u.call_msg.rpc_version != 2) {
        SLOG(LOG_DEBUG, "Rpc version should be 2, got %"PRIu32, info->u.call_msg.rpc_version);
        return PROTO_PARSE_ERR;
    }
    info->u.call_msg.program = cursor_read_u32n(cursor);
    info->u.call_msg.program_version = cursor_read_u32n(cursor);
    info->u.call_msg.procedure = cursor_read_u32n(cursor);

    RPC_CHECK_AUTH(credential);

    CHECK(2);
    RPC_CHECK_AUTH(auth);

    return PROTO_OK;
}

static enum proto_parse_status parse_rpc_reply(struct cursor *cursor, struct rpc_proto_info *info)
{
    info->u.reply_msg.reply_status = cursor_read_u32(cursor);
    switch (info->u.reply_msg.reply_status) {
        case RPC_MSG_ACCEPTED:
            {
                RPC_CHECK_AUTH(credential);
                break;
            }
        case RPC_MSG_DENIED:
            {
                enum rejected_status rejected_status = cursor_read_u32(cursor);
                if (rejected_status > RPC_AUTH_ERROR) return PROTO_PARSE_ERR;
                break;
            }
    }
    return PROTO_OK;
}

static enum proto_parse_status rpc_parse(struct parser *parser, struct proto_info *parent, unsigned unused_ way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const unused_ *now, size_t unused_ tot_cap_len, uint8_t const unused_ *tot_packet)
{
    struct cursor cursor;
    cursor_ctor(&cursor, packet, cap_len);
        if (wire_len < 12) return PROTO_PARSE_ERR;
        if (cap_len < 12) return PROTO_TOO_SHORT;

    ASSIGN_INFO_OPT(tcp, parent);

    struct rpc_proto_info info;
    proto_info_ctor(&info.info, parser, parent, wire_len, 0);

    if (tcp) cursor_drop(&cursor, 4); // Drop fragment header
    cursor_drop(&cursor, 4);
    info.msg_type = cursor_read_u32n(&cursor);
    enum proto_parse_status status = PROTO_OK;
    switch (info.msg_type) {
        case RPC_CALL:
            if (wire_len < 40) return PROTO_PARSE_ERR;
            if (cap_len < 40) return PROTO_TOO_SHORT;
            status = parse_rpc_call(&cursor, &info);
            break;
        case RPC_REPLY:
            status = parse_rpc_reply(&cursor, &info);
            break;
        default:
            return PROTO_PARSE_ERR;
    }
    SLOG(LOG_DEBUG, "Parsed rpc status %s, %s", proto_parse_status_2_str(status), rpc_info_2_str(&info.info));
    if (status == PROTO_OK) {
        // TODO We can have a nfs payload
        (void)proto_parse(NULL, &info.info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
    }
    return status;
}

static struct uniq_proto uniq_proto_rpc;
struct proto *proto_rpc = &uniq_proto_rpc.proto;
static struct port_muxer nfs_tcp_port_muxer;
static struct port_muxer nfs_udp_port_muxer;
static struct port_muxer sun_rpc_tcp_port_muxer;
static struct port_muxer sun_rpc_udp_port_muxer;

void rpc_init(void)
{
    log_category_proto_rpc_init();
    static struct proto_ops const ops = {
        .parse      = rpc_parse,
        .parser_new = uniq_parser_new,
        .parser_del = uniq_parser_del,
        .info_2_str = rpc_info_2_str,
        .info_addr  = proto_info_addr,
    };
    uniq_proto_ctor(&uniq_proto_rpc, &ops, "RPC", PROTO_CODE_RPC);
    port_muxer_ctor(&nfs_tcp_port_muxer, &tcp_port_muxers, 2049, 2049, proto_rpc);
    port_muxer_ctor(&nfs_udp_port_muxer, &udp_port_muxers, 2049, 2049, proto_rpc);
    port_muxer_ctor(&sun_rpc_tcp_port_muxer, &tcp_port_muxers, 111, 111, proto_rpc);
    port_muxer_ctor(&sun_rpc_udp_port_muxer, &udp_port_muxers, 111, 111, proto_rpc);
}

void rpc_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    port_muxer_dtor(&nfs_tcp_port_muxer, &tcp_port_muxers);
    port_muxer_dtor(&sun_rpc_tcp_port_muxer, &tcp_port_muxers);
    port_muxer_dtor(&nfs_udp_port_muxer, &udp_port_muxers);
    port_muxer_dtor(&sun_rpc_udp_port_muxer, &udp_port_muxers);
    uniq_proto_dtor(&uniq_proto_rpc);
#   endif

    log_category_proto_rpc_fini();
}

