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
#include "junkie/proto/cursor.h"
#include "junkie/proto/streambuf.h"
#include "junkie/proto/tcp.h"
#include "junkie/proto/rtp.h"
#include "junkie/proto/cnxtrack.h"
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

static char const *skinny_header_version_2_str(enum skinny_header_version ver)
{
    switch (ver) {
        case SKINNY_BASIC: return "Basic";
        case SKINNY_CM7_TYPE_A: return "CM7 type A";
        case SKINNY_CM7_TYPE_B: return "CM7 type B";
        case SKINNY_CM7_TYPE_C: return "CM7 type C";
    }
    return tempstr_printf("Unknown header ver 0x%X", ver);
}

static char const *skinny_msgid_2_str(enum skinny_msgid id)
{
    switch (id) {
        case SKINNY_STATION_KEEPALIVE: return "Keepalive";
        case SKINNY_STATION_REGISTER: return "Register";
        case SKINNY_STATION_IP_PORT: return "Ip port";
        case SKINNY_STATION_KEY_PAD_BUTTON: return "Key pad button";
        case SKINNY_STATION_ENBLOC_CALL: return "Enbloc call";
        case SKINNY_STATION_STIMULUS: return "Stimulus";
        case SKINNY_STATION_OFF_HOOK: return "Off hook";
        case SKINNY_STATION_ON_HOOK: return "On hook";
        case SKINNY_STATION_HOOK_FLASH: return "Hook flash";
        case SKINNY_STATION_FORWARD_STATUS_REQ: return "Forward status request";
        case SKINNY_STATION_SPEED_DIAL_STATUS_REQ: return "Speed dial status request";
        case SKINNY_STATION_LINE_STATUS_REQ: return "Line status request";
        case SKINNY_STATION_CONFIGURATION_STATUS_REQ: return "Configuration status request";
        case SKINNY_STATION_TIME_DATE_REQ: return "Time date request";
        case SKINNY_STATION_BUTTON_TEMPLATE_REQ: return "Button template request";
        case SKINNY_STATION_VERSION_REQ: return "Version request";
        case SKINNY_STATION_CAPABILITIES_RESP: return "Capabilities response";
        case SKINNY_STATION_MEDIA_PORT_LIST: return "Media port list";
        case SKINNY_STATION_SERVER_REQ: return "Server request";
        case SKINNY_STATION_ALARM: return "Alarm";
        case SKINNY_STATION_MULTICAST_MEDIA_RECEPT_ACK: return "Multicast media reception ack";
        case SKINNY_STATION_OFF_HOOK_WITH_CALLING_PARTY_NUMBER: return "Off hook with calling party number";
        case SKINNY_STATION_OPEN_RECV_CHANNEL_ACK: return "Open receive channel ack";
        case SKINNY_STATION_CONNECTION_STATISTICS_RESP: return "Connection statistics response";
        case SKINNY_STATION_SOFT_KEY_TEMPLATE_REQ: return "Soft key template request";
        case SKINNY_STATION_SOFT_KEY_SET_REQ: return "Soft key set request";
        case SKINNY_STATION_SOFT_KEY_EVENT: return "Soft key event";
        case SKINNY_STATION_UNREGISTER: return "Unregister";
        case SKINNY_STATION_REGISTER_TOKEN_REQ: return "Register token request";
        case SKINNY_STATION_MEDIA_TRANSMIT_FAILURE: return "Media transmit failure";
        case SKINNY_STATION_HEADSET_STATUS: return "Headset status";
        case SKINNY_STATION_MEDIA_RESOURCE_NOTIF: return "Media resource notif";
        case SKINNY_STATION_REGISTER_AVAILABLE_LINES: return "Register available lines";
        case SKINNY_STATION_DEVICE_TO_USER_DATA: return "Device to user data";
        case SKINNY_STATION_DEVICE_TO_USER_DATA_RESP: return "Device to user data response";
        case SKINNY_STATION_UPDATE_CAPABILITIES: return "Update capabilities";
        case SKINNY_STATION_OPEN_MULTIMEDIA_RECV_CHANNEL_ACK: return "Open multimedia receive channel ack";
        case SKINNY_STATION_CLEAR_CONFERENCE: return "Clear conference";
        case SKINNY_STATION_SERVICE_URLSTAT_REQ: return "Service urlstat request";
        case SKINNY_STATION_FEATURE_STAT_REQ: return "Feature stat request";
        case SKINNY_STATION_CREATE_CONFERENCE_RES: return "Create conference res";
        case SKINNY_STATION_DELETE_CONFERENCE_RES: return "Delete conference res";
        case SKINNY_STATION_MODIFY_CONFERENCE_RES: return "Modify conference res";
        case SKINNY_STATION_ADD_PARTICIPANT_RES: return "Add participant res";
        case SKINNY_STATION_AUDIT_CONFERENCE_RES: return "Audit conference res";
        case SKINNY_STATION_AUDIT_PARTICIPANT_RES: return "Audit participant res";
        case SKINNY_STATION_DEVICE_TO_USER_DATA_VERSION1: return "Device to user data version1";
        case SKINNY_STATION_DEVICE_TO_USER_DATA_RESP_VERSION1: return "Device to user data response version1";
        case SKINNY_STATION_DIALED_PHONE_BOOK: return "Dialed phone book";
        case SKINNY_MGR_KEEPALIVE: return "Keepalive";
        case SKINNY_MGR_START_TONE: return "Start tone";
        case SKINNY_MGR_STOP_TONE: return "Stop tone";
        case SKINNY_MGR_SET_RINGER: return "Set ringer";
        case SKINNY_MGR_SET_LAMP: return "Set lamp";
        case SKINNY_MGR_SET_HOOK_FLASH_DETECT: return "Set hook flash detect";
        case SKINNY_MGR_SET_SPEAKER_MODE: return "Set speaker mode";
        case SKINNY_MGR_SET_MICROPHONE_MODE: return "Set microphone mode";
        case SKINNY_MGR_START_MEDIA_TRANSMIT: return "Start media transmission";
        case SKINNY_MGR_STOP_MEDIA_TRANSMIT: return "Stop media transmission";
        case SKINNY_MGR_START_MEDIA_RECEPTION: return "Start media reception";
        case SKINNY_MGR_STOP_MEDIA_RECEPTION: return "Stop media reception";
        case SKINNY_MGR_CALL_INFORMATION: return "Call information";
        case SKINNY_MGR_REGISTER_REJECT: return "Register reject";
        case SKINNY_MGR_RESET: return "Reset";
        case SKINNY_MGR_KEEPALIVE_ACK: return "Keepalive ack";
        case SKINNY_MGR_FORWARD_STATUS: return "Forward status";
        case SKINNY_MGR_SPEED_DIAL_STATUS: return "Speed dial status";
        case SKINNY_MGR_LINE_STATUS: return "Line status";
        case SKINNY_MGR_CONFIGURATION_STATUS: return "Configuration status";
        case SKINNY_MGR_DEFINE_TIME_N_DATE: return "Define time & date";
        case SKINNY_MGR_START_SESSION_TRANSMIT: return "Start session transmission";
        case SKINNY_MGR_STOP_SESSION_TRANSMIT: return "Stop session transmission";
        case SKINNY_MGR_BUTTON_TEMPLATE: return "Button template";
        case SKINNY_MGR_VERSION: return "Version";
        case SKINNY_MGR_DISPLAY_TEXT: return "Display text";
        case SKINNY_MGR_CLEAR_DISPLAY: return "Clear display";
        case SKINNY_MGR_CAPABILITIES_REQ: return "Capabilities request";
        case SKINNY_MGR_ENUNCIATOR_COMMAND: return "Enunciator command";
        case SKINNY_MGR_SERVER_RESP: return "Server respond";
        case SKINNY_MGR_START_MULTICAST_MEDIA_RECEPT: return "Start multicast media reception";
        case SKINNY_MGR_START_MULTICAST_MEDIA_TRANSMIT: return "Start multicast media transmission";
        case SKINNY_MGR_STOP_MULTICAST_MEDIA_RECEPT: return "Stop multicast media reception";
        case SKINNY_MGR_STOP_MULTICAST_MEDIA_TRANSMIT: return "Stop multicast media transmission";
        case SKINNY_MGR_OPEN_RECV_CHANNEL: return "Open receive channel";
        case SKINNY_MGR_CLOSE_RECV_CHANNEL: return "Close receive channel";
        case SKINNY_MGR_CONNECTION_STATISTICS_REQ: return "Connection statistics request";
        case SKINNY_MGR_SOFT_KEY_TEMPLATE_RESP: return "Soft key template respond";
        case SKINNY_MGR_SOFT_KEY_SET_RESP: return "Soft key set respond";
        case SKINNY_MGR_SELECT_SOFT_KEYS: return "Select soft keys";
        case SKINNY_MGR_CALL_STATE: return "Call state";
        case SKINNY_MGR_DISPLAY_PROMPT: return "Display prompt";
        case SKINNY_MGR_CLEAR_PROMPT: return "Clear prompt";
        case SKINNY_MGR_DISPLAY_NOTIFY: return "Display notify";
        case SKINNY_MGR_CLEAR_NOTIFY: return "Clear notify";
        case SKINNY_MGR_ACTIVATE_CALL_PLANE: return "Activate call plane";
        case SKINNY_MGR_DEACTIVATE_CALL_PLANE: return "Deactivate call plane";
        case SKINNY_MGR_UNREGISTER_ACK: return "Unregister ack";
        case SKINNY_MGR_BACK_SPACE_REQ: return "Back space request";
        case SKINNY_MGR_REGISTER_TOKEN_ACK: return "Register token ack";
        case SKINNY_MGR_REGISTER_TOKEN_REJECT: return "Register token reject";
        case SKINNY_MGR_START_MEDIA_FAILURE_DETECTION: return "Start media failure detection";
        case SKINNY_MGR_DIALED_NUMBER: return "Dialed number";
        case SKINNY_MGR_USER_TO_DEVICE_DATA: return "User to device data";
        case SKINNY_MGR_FEATURE_STAT: return "Feature stat";
        case SKINNY_MGR_DISPLAY_PRI_NOTIFY: return "Display pri notify";
        case SKINNY_MGR_CLEAR_PRI_NOTIFY: return "Clear pri notify";
        case SKINNY_MGR_START_ANNOUNCE: return "Start announce";
        case SKINNY_MGR_STOP_ANNOUNCE: return "Stop announce";
        case SKINNY_MGR_ANNOUNCE_FINISH: return "Announce finish";
        case SKINNY_MGR_NOTIFY_DTMF_TONE: return "Notify dtmf tone";
        case SKINNY_MGR_SEND_DTMF_TONE: return "Send dtmf tone";
        case SKINNY_MGR_SUBSCRIBE_DTMF_PAYLOAD_REQ: return "Subscribe dtmf payload request";
        case SKINNY_MGR_SUBSCRIBE_DTMF_PAYLOAD_RES: return "Subscribe dtmf payload res";
        case SKINNY_MGR_SUBSCRIBE_DTMF_PAYLOAD_ERR: return "Subscribe dtmf payload err";
        case SKINNY_MGR_UNSUBSCRIBE_DTMF_PAYLOAD_REQ: return "Unsubscribe dtmf payload request";
        case SKINNY_MGR_UNSUBSCRIBE_DTMF_PAYLOAD_RES: return "Unsubscribe dtmf payload res";
        case SKINNY_MGR_UNSUBSCRIBE_DTMF_PAYLOAD_ERR: return "Unsubscribe dtmf payload err";
        case SKINNY_MGR_SERVICE_URLSTAT: return "Service urlstat";
        case SKINNY_MGR_CALL_SELECT_STAT: return "Call select stat";
        case SKINNY_MGR_OPEN_MULTIMEDIA_CHANNEL: return "Open multimedia channel";
        case SKINNY_MGR_START_MULTIMEDIA_TRANSMIT: return "Start multimedia transmit";
        case SKINNY_MGR_STOP_MULTIMEDIA_TRANSMIT: return "Stop multimedia transmit";
        case SKINNY_MGR_MISCELLANEOUS_COMMAND: return "Miscellaneous command";
        case SKINNY_MGR_FLOW_CONTROL_COMMAND: return "Flow control command";
        case SKINNY_MGR_CLOSE_MULTIMEDIA_RECV_CHANNEL: return "Close multimedia receive channel";
        case SKINNY_MGR_CREATE_CONFERENCE_REQ: return "Create conference request";
        case SKINNY_MGR_DELETE_CONFERENCE_REQ: return "Delete conference request";
        case SKINNY_MGR_MODIFY_CONFERENCE_REQ: return "Modify conference request";
        case SKINNY_MGR_ADD_PARTICIPANT_REQ: return "Add participant request";
        case SKINNY_MGR_DROP_PARTICIPANT_REQ: return "Drop participant request";
        case SKINNY_MGR_AUDIT_CONFERENCE_REQ: return "Audit conference request";
        case SKINNY_MGR_AUDIT_PARTICIPANT_REQ: return "Audit participant request";
        case SKINNY_MGR_USER_TO_DEVICE_DATA_VERSION1: return "User to device data version1";
        case SKINNY_MGR_CALL_INFO: return "Call info";
        case SKINNY_MGR_DIALED_PHONE_BOOK_ACK: return "Dialed phone book ack";
        case SKINNY_MGR_XMLALARM: return "Xmlalarm";
    }
    return tempstr_printf("Unknown msgid 0x%X", id);
}

static char const *skinny_call_state_2_str(enum skinny_call_state st) {
    switch (st) {
        case SKINNY_OFF_HOOK: return "off hook";
        case SKINNY_ON_HOOK: return "on hook";
        case SKINNY_RING_OUT: return "ring out";
        case SKINNY_RING_IN: return "ring in";
        case SKINNY_CONNECTED: return "connected";
        case SKINNY_BUSY: return "busy";
        case SKINNY_CONGESTION: return "congestion";
        case SKINNY_HOLD: return "hold";
        case SKINNY_CALL_WAITING: return "call waiting";
        case SKINNY_CALL_TRANSFER: return "call transfer";
        case SKINNY_CALL_PARK: return "call park";
        case SKINNY_PROCEED: return "proceed";
        case SKINNY_REMOTE_MULTILINE: return "remote multiline";
        case SKINNY_INVALID_NUMBER: return "invalid number";
    }
    return tempstr_printf("Unknown call state %u", st);
}

static char const *skinny_info_2_str(struct proto_info const *info_)
{
    struct skinny_proto_info const *info = DOWNCAST(info_, info, skinny_proto_info);
    return tempstr_printf("%s, HeaderVer:%s, MsgId:%s%s%s%s%s%s%s%s%s%s",
        proto_info_2_str(&info->info),
        skinny_header_version_2_str(info->header_ver),
        skinny_msgid_2_str(info->msgid),
        info->set_values & SKINNY_NEW_KEY_PAD   ? tempstr_printf(", Key:%"PRIu32,        info->new_key_pad):"",
        info->set_values & SKINNY_LINE_INSTANCE ? tempstr_printf(", Line:%"PRIu32,       info->line_instance):"",
        info->set_values & SKINNY_CALL_ID       ? tempstr_printf(", CallId:%"PRIu32,     info->call_id):"",
        info->set_values & SKINNY_CONFERENCE_ID ? tempstr_printf(", ConfId:%"PRIu32,     info->conf_id):"",
        info->set_values & SKINNY_PASS_THRU_ID  ? tempstr_printf(", PassThruId:%"PRIu32, info->pass_thru_id):"",
        info->set_values & SKINNY_CALL_STATE    ? tempstr_printf(", CallState:%s", skinny_call_state_2_str(info->call_state)):"",
        info->set_values & SKINNY_MEDIA_CNX     ? tempstr_printf(", MediaIp:%s:%"PRIu16, ip_addr_2_str(&info->media_ip), info->media_port):"",
        info->set_values & SKINNY_CALLING_PARTY ? tempstr_printf(", CallingParty:%s",    info->calling_party):"",
        info->set_values & SKINNY_CALLED_PARTY  ? tempstr_printf(", CalledParty:%s",     info->called_party):"");
}

static void skinny_proto_info_ctor(struct skinny_proto_info *info, struct parser *parser, struct proto_info *parent, size_t head_len, size_t payload, enum skinny_msgid msg_id, uint32_t header_ver)
{
    proto_info_ctor(&info->info, parser, parent, head_len, payload);
    info->set_values = 0;
    info->msgid = msg_id;
    info->header_ver = header_ver;
}

/*
 * Parse
 */

struct skinny_parser {
    struct parser parser;
    struct streambuf sbuf;
#   define FROM_STATION 0
#   define FROM_MGR 1
    bool media_set[2];          // from station/msg
    struct ip_addr peer[2];     // from station/mgr
    uint16_t port[2];           // from station/mgr
};

static parse_fun skinny_sbuf_parse;
static int skinny_parser_ctor(struct skinny_parser *skinny_parser, struct proto *proto)
{
    SLOG(LOG_DEBUG, "Construct SKINNY parser@%p", skinny_parser);

    assert(proto == proto_skinny);
    if (0 != parser_ctor(&skinny_parser->parser, proto)) return -1;
#   define SKINNY_MAX_HDR_SIZE 1000   // in bytes
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

static void try_cnxtrack(struct skinny_parser *parser, struct timeval const *now)
{
    if (!parser->media_set[FROM_MGR] || !parser->media_set[FROM_STATION]) return;

    spawn_rtp_subparsers(&parser->peer[FROM_STATION], parser->port[FROM_STATION], &parser->peer[FROM_MGR], parser->port[FROM_MGR], now, proto_skinny);
    parser->media_set[FROM_MGR] = parser->media_set[FROM_STATION] = false;
}

static enum proto_parse_status read_channel(struct skinny_parser *parser, unsigned from, struct skinny_proto_info *info, struct cursor *curs, struct timeval const *now)
{
    assert(from == FROM_MGR || from == FROM_STATION);
    if (curs->cap_len < 4+16+4) return PROTO_TOO_SHORT;

    uint32_t ip_version = 0;
    // The ip field has a 16 byte lenght on CM7 headers. We
    // need to drop some bytes before parsing remote port
    short offset_ip_port = 0;
    switch (info->header_ver) {
        case SKINNY_BASIC:
            break;
        case SKINNY_CM7_TYPE_A:
        case SKINNY_CM7_TYPE_B:
        case SKINNY_CM7_TYPE_C:
            ip_version = cursor_read_u32le(curs);
            // We drop (16 - 4) for ipv4 and (16 - 8) for ipv6
            offset_ip_port = ip_version ? 8 : 12;
            break;
    }

    if (ip_version == 0) {  // v4
        uint32_t ip = cursor_read_u32(curs);
        ip_addr_ctor_from_ip4(&parser->peer[from], ip);
    } else if (ip_version == 1) {    // v6
        ip_addr_ctor_from_ip6(&parser->peer[from], *(struct in6_addr const *)curs->head);
    } else {
        SLOG(LOG_DEBUG, "Invalid IP version (%d)", ip_version);
        return PROTO_PARSE_ERR;
    }

    cursor_drop(curs, offset_ip_port);
    parser->port[from] = cursor_read_u32le(curs);
    parser->media_set[from] = true;
    try_cnxtrack(parser, now);

    // Copy these into the info block
    SLOG(LOG_DEBUG, "Got media info");
    info->set_values |= SKINNY_MEDIA_CNX;
    info->media_ip = parser->peer[from];
    info->media_port = parser->port[from];

    return PROTO_OK;
}

static enum proto_parse_status read_string(char *dest, size_t max_size, struct cursor *curs)
{
    // This is an error to not reach '\0' before the end of the cursor
    while (curs->cap_len > 0 && curs->head[0] != '\0') {
        if (max_size > 1) {
            max_size --;
            *dest ++ = cursor_read_u8(curs);
        } else {    // we suppose, if this does not fit in max_size, that we are not parsing Skinny
            return PROTO_PARSE_ERR;
        }
    }
    if (! curs->cap_len) return PROTO_TOO_SHORT;
    *dest ++ = cursor_read_u8(curs);    // the nul
    return PROTO_OK;
}

static enum proto_parse_status skinny_sbuf_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct skinny_parser *skinny_parser = DOWNCAST(parser, parser, skinny_parser);

#   define SKINNY_HDR_SIZE 8
#   define SKINNY_MIN_MSG_SIZE 12
    if (wire_len < SKINNY_MIN_MSG_SIZE) {
        streambuf_set_restart(&skinny_parser->sbuf, way, packet, true); // wait for more
        return PROTO_OK;
    }
    if (cap_len < SKINNY_MIN_MSG_SIZE) return PROTO_TOO_SHORT;

    struct cursor curs;
    cursor_ctor(&curs, packet, cap_len);
    uint32_t msg_len = cursor_read_u32le(&curs);
    enum skinny_header_version header_ver = cursor_read_u32le(&curs);
    enum skinny_msgid msg_id = cursor_read_u32le(&curs);
    SLOG(LOG_DEBUG, "New SKINNY msg of size %"PRIu32", msgid=0x%"PRIx32, msg_len, msg_id);
    if (header_ver != SKINNY_BASIC && header_ver != SKINNY_CM7_TYPE_A && header_ver != SKINNY_CM7_TYPE_B && header_ver != SKINNY_CM7_TYPE_C) return PROTO_PARSE_ERR;
    if (msg_len < 4 || msg_len > SKINNY_MAX_HDR_SIZE /* guestimated */) return PROTO_PARSE_ERR;
    if (wire_len < msg_len + SKINNY_HDR_SIZE) return PROTO_TOO_SHORT; // wait for the message to be complete
    // Ok we have what looks like a skinny message in there
    struct skinny_proto_info info;
    skinny_proto_info_ctor(&info, parser, parent, SKINNY_HDR_SIZE, msg_len, msg_id, header_ver);
    switch (msg_id) {
        case SKINNY_STATION_KEY_PAD_BUTTON:
            if (curs.cap_len < 12) return PROTO_TOO_SHORT;
            info.set_values |= SKINNY_NEW_KEY_PAD | SKINNY_LINE_INSTANCE | SKINNY_CALL_ID;
            info.new_key_pad = cursor_read_u32le(&curs);
            info.line_instance = cursor_read_u32le(&curs);
            info.call_id = cursor_read_u32le(&curs);
            break;
        case SKINNY_MGR_CALL_STATE:
            if (curs.cap_len < 12) return PROTO_TOO_SHORT;
            info.set_values |= SKINNY_CALL_STATE | SKINNY_LINE_INSTANCE | SKINNY_CALL_ID;
            info.call_state = cursor_read_u32le(&curs);
            info.line_instance = cursor_read_u32le(&curs);
            info.call_id = cursor_read_u32le(&curs);
            SLOG(LOG_DEBUG, "New call state: %s", skinny_call_state_2_str(info.call_state));
            break;
        case SKINNY_MGR_CLOSE_RECV_CHANNEL:
        case SKINNY_MGR_STOP_MEDIA_TRANSMIT:
            if (curs.cap_len < 8) return PROTO_TOO_SHORT;
            info.set_values |= SKINNY_CONFERENCE_ID | SKINNY_PASS_THRU_ID;
            info.conf_id = cursor_read_u32le(&curs);
            info.pass_thru_id = cursor_read_u32le(&curs);
            break;
        case SKINNY_MGR_START_MEDIA_TRANSMIT:
            if (curs.cap_len < 8) return PROTO_TOO_SHORT;
            info.set_values |= SKINNY_CONFERENCE_ID | SKINNY_PASS_THRU_ID;
            info.conf_id = cursor_read_u32le(&curs);
            info.pass_thru_id = cursor_read_u32le(&curs);
            enum proto_parse_status status = read_channel(skinny_parser, FROM_MGR, &info, &curs, now);
            if (PROTO_OK != status) return status;
            break;
        case SKINNY_STATION_OPEN_RECV_CHANNEL_ACK:
            if (curs.cap_len < 4) return PROTO_TOO_SHORT;
            uint32_t open_status = cursor_read_u32le(&curs);
            if (open_status == 0 /* Ok */) {
                enum proto_parse_status status = read_channel(skinny_parser, FROM_STATION, &info, &curs, now);
                if (PROTO_OK != status) return status;
                info.set_values |= SKINNY_PASS_THRU_ID;
                if (curs.cap_len < 4) return PROTO_TOO_SHORT;
                info.pass_thru_id = cursor_read_u32le(&curs);
            }
            break;
        case SKINNY_MGR_OPEN_RECV_CHANNEL:
            if (curs.cap_len < 8) return PROTO_TOO_SHORT;
            info.set_values |= SKINNY_CONFERENCE_ID | SKINNY_PASS_THRU_ID;
            info.conf_id = cursor_read_u32le(&curs);
            info.pass_thru_id = cursor_read_u32le(&curs);
            break;
        case SKINNY_MGR_DIALED_NUMBER:
#           define DIALED_NUMBER_SIZE 24
            if (curs.cap_len < DIALED_NUMBER_SIZE+8) return PROTO_TOO_SHORT;
            info.set_values |= SKINNY_CALLED_PARTY | SKINNY_LINE_INSTANCE | SKINNY_CALL_ID;
            // 24 chars, terminated with 0 (if fits)
            snprintf(info.called_party, sizeof(info.called_party), "%.*s", (int)DIALED_NUMBER_SIZE, curs.head);
            cursor_drop(&curs, DIALED_NUMBER_SIZE);
            info.line_instance = cursor_read_u32le(&curs);
            info.call_id = cursor_read_u32le(&curs);
            break;
        case SKINNY_MGR_CALL_INFO:
            if (curs.cap_len < 8 + 4 + 5*4) return PROTO_TOO_SHORT;
            info.set_values |= SKINNY_CALLING_PARTY | SKINNY_CALLED_PARTY | SKINNY_LINE_INSTANCE | SKINNY_CALL_ID;
            info.line_instance = cursor_read_u32le(&curs);
            info.call_id = cursor_read_u32le(&curs);
            cursor_drop(&curs, 4 + 5*4);  // drop Call Type and 5 unknown fields
            // From now on, informations are nul terminated strings
            if (PROTO_OK != (status = read_string(info.calling_party, sizeof(info.calling_party), &curs))) return status; // Calling party
            if (header_ver == SKINNY_CM7_TYPE_A || header_ver == SKINNY_CM7_TYPE_B || header_ver == SKINNY_CM7_TYPE_C) {
                    cursor_read_string(&curs, NULL, 24); // Drop calling party voice mailbox
            }
            if (PROTO_OK != (status = read_string(info.called_party,  sizeof(info.called_party),  &curs))) return status; // Called party
            // discard the rest of informations
            break;
        default:
            break;
    }
    (void)proto_parse(NULL, &info.info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);

    streambuf_set_restart(&skinny_parser->sbuf, way, packet + SKINNY_HDR_SIZE + msg_len, false); // go to next msg

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
        .info_addr   = skinny_info_addr
    };
    proto_ctor(&proto_skinny_, &ops, "SKINNY", PROTO_CODE_SKINNY);
    port_muxer_ctor(&tcp_port_muxer, &tcp_port_muxers, SKINNY_PORT, SKINNY_PORT, proto_skinny);
}

void skinny_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    port_muxer_dtor(&tcp_port_muxer, &tcp_port_muxers);
    proto_dtor(&proto_skinny_);
#   endif
    log_category_proto_skinny_fini();
}

