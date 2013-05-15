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
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include "junkie/tools/objalloc.h"
#include "junkie/proto/serialize.h"
#include "junkie/proto/streambuf.h"
#include "junkie/proto/tcp.h"
#include "junkie/proto/skinny.h"

#undef LOG_CAT
#define LOG_CAT proto_skinny_log_category

LOG_CATEGORY_DEF(proto_skinny);

#define SKINNY_PORT 2000

/*
 * Proto Infos
 */

static void const *skinny_info_addr(struct proto_info const *info_, size_t *size)
{
    struct skinny_proto_info const *info = DOWNCAST(info_, info, skinny_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *skinny_msgid_2_str(enum skinny_msgid id)
{
    switch (id) {
        case SKINNY_KEEPALIVE: return "Keepalive";
        case SKINNY_REGISTER: return "Register";
        case SKINNY_IP_PORT: return "Ip port";
        case SKINNY_KEY_PAD_BUTTON: return "Key pad button";
        case SKINNY_ENBLOC_CALL: return "Enbloc call";
        case SKINNY_STIMULUS: return "Stimulus";
        case SKINNY_OFF_HOOK: return "Off hook";
        case SKINNY_ON_HOOK: return "On hook";
        case SKINNY_HOOK_FLASH: return "Hook flash";
        case SKINNY_FORWARD_STATUS_REQ: return "Forward status request";
        case SKINNY_SPEED_DIAL_STATUS_REQ: return "Speed dial status request";
        case SKINNY_LINE_STATUS_REQ: return "Line status request";
        case SKINNY_CONFIGURATION_STATUS_REQ: return "Configuration status request";
        case SKINNY_TIME_DATE_REQ: return "Time date request";
        case SKINNY_BUTTON_TEMPLATE_REQ: return "Button template request";
        case SKINNY_VERSION_REQ: return "Version request";
        case SKINNY_CAPABILITIES_RESPONSE: return "Capabilities response";
        case SKINNY_MEDIA_PORT_LIST: return "Media port list";
        case SKINNY_SERVER_REQ: return "Server request";
        case SKINNY_ALARM: return "Alarm";
        case SKINNY_MULTICAST_MEDIA_RECEPT_ACK: return "Multicast media reception ack";
        case SKINNY_OFF_HOOK_WITH_CALLING_PARTY_NUMBER: return "Off hook with calling party number";
        case SKINNY_OPEN_RECEIVE_CHANNEL_ACK: return "Open receive channel ack";
        case SKINNY_CONNECTION_STATISTICS_RESPONSE: return "Connection statistics response";
        case SKINNY_SOFT_KEY_TEMPLATE_REQ: return "Soft key template request";
        case SKINNY_SOFT_KEY_SET_REQ: return "Soft key set request";
        case SKINNY_SOFT_KEY_EVENT: return "Soft key event";
        case SKINNY_UNREGISTER: return "Unregister";
        case SKINNY_KEEP_ALIVE: return "Keep alive";
        case SKINNY_START_TONE: return "Start tone";
        case SKINNY_STOP_TONE: return "Stop tone";
        case SKINNY_SET_RINGER: return "Set ringer";
        case SKINNY_SET_LAMP: return "Set lamp";
        case SKINNY_SET_HOOK_FLASH_DETECT: return "Set hook flash detect";
        case SKINNY_SET_SPEAKER_MODE: return "Set speaker mode";
        case SKINNY_SET_MICROPHONE_MODE: return "Set microphone mode";
        case SKINNY_START_MEDIA_TRANSMIT: return "Start media transmission";
        case SKINNY_STOP_MEDIA_TRANSMIT: return "Stop media transmission";
        case SKINNY_CALL_INFORMATION: return "Call information";
        case SKINNY_REGISTER_REJECT: return "Register reject";
        case SKINNY_RESET: return "Reset";
        case SKINNY_FORWARD_STATUS: return "Forward status";
        case SKINNY_SPEED_DIAL_STATUS: return "Speed dial status";
        case SKINNY_LINE_STATUS: return "Line status";
        case SKINNY_CONFIGURATION_STATUS: return "Configuration status";
        case SKINNY_DEFINE_TIME_N_DATE: return "Define time & date";
        case SKINNY_START_SESSION_TRANSMIT: return "Start session transmission";
        case SKINNY_STOP_SESSION_TRANSMIT: return "Stop session transmission";
        case SKINNY_BUTTON_TEMPLATE: return "Button template";
        case SKINNY_VERSION: return "Version";
        case SKINNY_DISPLAY_TEXT: return "Display text";
        case SKINNY_CLEAR_DISPLAY: return "Clear display";
        case SKINNY_CAPABILITIES_REQ: return "Capabilities request";
        case SKINNY_ENUNCIATOR_COMMAND: return "Enunciator command";
        case SKINNY_SERVER_RESP: return "Server respond";
        case SKINNY_START_MULTICAST_MEDIA_RECEPT: return "Start multicast media reception";
        case SKINNY_START_MULTICAST_MEDIA_TRANSMIT: return "Start multicast media transmission";
        case SKINNY_STOP_MULTICAST_MEDIA_RECEPT: return "Stop multicast media reception";
        case SKINNY_STOP_MULTICAST_MEDIA_TRANSMIT: return "Stop multicast media transmission";
        case SKINNY_OPEN_RECEIVE_CHANNEL: return "Open receive channel";
        case SKINNY_CLOSE_RECEIVE_CHANNEL: return "Close receive channel";
        case SKINNY_CONNECTION_STATISTICS_REQ: return "Connection statistics request";
        case SKINNY_SOFT_KEY_TEMPLATE_RESP: return "Soft key template respond";
        case SKINNY_SOFT_KEY_SET_RESP: return "Soft key set respond";
        case SKINNY_SELECT_SOFT_KEYS: return "Select soft keys";
        case SKINNY_CALL_STATE: return "Call state";
        case SKINNY_DISPLAY_PROMPT: return "Display prompt";
        case SKINNY_CLEAR_PROMPT: return "Clear prompt";
        case SKINNY_DISPLAY_NOTIFY: return "Display notify";
        case SKINNY_CLEAR_NOTIFY: return "Clear notify";
        case SKINNY_ACTIVATE_CALL_PLANE: return "Activate call plane";
        case SKINNY_DEACTIVATE_CALL_PLANE: return "Deactivate call plane";
        case SKINNY_UNREGISTER_ACK: return "Unregister ack";
    }
    return tempstr_printf("Unknown msgid 0x%X", id);
}

static char const *skinny_info_2_str(struct proto_info const *info_)
{
    struct skinny_proto_info const *info = DOWNCAST(info_, info, skinny_proto_info);
    return tempstr_printf("%s, %s",
        proto_info_2_str(&info->info),
        skinny_msgid_2_str(info->msgid));
}

static void skinny_serialize(struct proto_info const *info_, uint8_t **buf)
{
    struct skinny_proto_info const *info = DOWNCAST(info_, info, skinny_proto_info);
    proto_info_serialize(&info->info, buf);
}

static void skinny_deserialize(struct proto_info *info_, uint8_t const **buf)
{
    struct skinny_proto_info *info = DOWNCAST(info_, info, skinny_proto_info);
    proto_info_deserialize(&info->info, buf);
}

static void skinny_proto_info_ctor(struct skinny_proto_info *info, struct parser *parser, struct proto_info *parent, size_t head_len, size_t payload)
{
    proto_info_ctor(&info->info, parser, parent, head_len, payload);
}

/*
 * Parse
 */

struct skinny_parser {
    struct parser parser;
    struct streambuf sbuf;
};

static parse_fun skinny_sbuf_parse;
static int skinny_parser_ctor(struct skinny_parser *skinny_parser, struct proto *proto)
{
    SLOG(LOG_DEBUG, "Construct SKINNY parser@%p", skinny_parser);

    assert(proto == proto_skinny);
    if (0 != parser_ctor(&skinny_parser->parser, proto)) return -1;
#   define SKINNY_MAX_HDR_SIZE 200   // in bytes
    if (0 != streambuf_ctor(&skinny_parser->sbuf, skinny_sbuf_parse, SKINNY_MAX_HDR_SIZE)) return -1;

    return 0;
}

static struct parser *skinny_parser_new(struct proto *proto)
{
    struct skinny_parser *skinny_parser = objalloc_nice(sizeof(*skinny_parser), "SKINNY parsers");
    if (! skinny_parser) return NULL;

    if (-1 == skinny_parser_ctor(skinny_parser, proto)) {
        objfree(skinny_parser);
        return NULL;
    }

    return &skinny_parser->parser;
}

static void skinny_parser_dtor(struct skinny_parser *skinny_parser)
{
    SLOG(LOG_DEBUG, "Destruct SKINNY parser@%p", skinny_parser);

    parser_dtor(&skinny_parser->parser);
    streambuf_dtor(&skinny_parser->sbuf);
}

static void skinny_parser_del(struct parser *parser)
{
    struct skinny_parser *skinny_parser = DOWNCAST(parser, parser, skinny_parser);
    skinny_parser_dtor(skinny_parser);
    objfree(skinny_parser);
}

static enum proto_parse_status skinny_sbuf_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct skinny_parser *skinny_parser = DOWNCAST(parser, parser, skinny_parser);

#   define SKINNY_MIN_HDR_SIZE 12
    if (wire_len < SKINNY_MIN_HDR_SIZE) {
        streambuf_set_restart(&skinny_parser->sbuf, way, packet, true); // wait for more
        return PROTO_OK;
    }
    if (cap_len < SKINNY_MIN_HDR_SIZE) return PROTO_TOO_SHORT;

    uint32_t msg_len = READ_U32LE(packet);
    uint32_t header_ver = READ_U32LE(packet+4);
    enum skinny_msgid msg_id = READ_U32LE(packet+8);
    if (header_ver != 0) return PROTO_PARSE_ERR;
    if (msg_len < 4 || msg_len > SKINNY_MAX_HDR_SIZE /* guestimated */) return PROTO_PARSE_ERR;
    msg_len -= 4;   // since the msg_id was counted
    if (wire_len < msg_len) return PROTO_TOO_SHORT; // wait for the message to be complete
    // Ok we have what looks like a skinny message in there
    struct skinny_proto_info info;
    skinny_proto_info_ctor(&info, parser, parent, SKINNY_MIN_HDR_SIZE, msg_len);
    info.msgid = msg_id;
    (void)proto_parse(NULL, &info.info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);

    streambuf_set_restart(&skinny_parser->sbuf, way, packet + 12 + msg_len, false); // go to next msg

    return PROTO_OK;
}

static enum proto_parse_status skinny_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct skinny_parser *skinny_parser = DOWNCAST(parser, parser, skinny_parser);
    return streambuf_add(&skinny_parser->sbuf, parser, parent, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);
}

/*
 * Init
 */

static struct proto proto_skinny_;
struct proto *proto_skinny = &proto_skinny_;
static struct port_muxer tcp_port_muxer;

void skinny_init(void)
{
    log_category_proto_skinny_init();

    static struct proto_ops const ops = {
        .parse       = skinny_parse,
        .parser_new  = skinny_parser_new,
        .parser_del  = skinny_parser_del,
        .info_2_str  = skinny_info_2_str,
        .info_addr   = skinny_info_addr,
        .serialize   = skinny_serialize,
        .deserialize = skinny_deserialize,
    };
    proto_ctor(&proto_skinny_, &ops, "SKINNY", PROTO_CODE_SKINNY);
    port_muxer_ctor(&tcp_port_muxer, &tcp_port_muxers, SKINNY_PORT, SKINNY_PORT, proto_skinny);
}

void skinny_fini(void)
{
    port_muxer_dtor(&tcp_port_muxer, &tcp_port_muxers);
    proto_dtor(&proto_skinny_);
    log_category_proto_skinny_fini();
}

