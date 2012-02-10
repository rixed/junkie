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
#include "junkie/tools/mallocer.h"
#include "junkie/tools/tempstr.h"
#include "junkie/proto/serialize.h"
#include "junkie/proto/udp.h"
#include "junkie/proto/sdp.h"
#include "junkie/proto/mgcp.h"
#include "proto/liner.h"

#undef LOG_CAT
#define LOG_CAT proto_mgcp_log_category

LOG_CATEGORY_DEF(proto_mgcp);

/*
 * We implement our own parser in order to store an sdp_parser
 */

struct mgcp_parser {
    struct parser parser;
    struct parser *sdp_parser;
};

static int mgcp_parser_ctor(struct mgcp_parser *mgcp_parser, struct proto unused_ *proto)
{
    assert(proto == proto_mgcp);
    if (0 != parser_ctor(&mgcp_parser->parser, proto_mgcp)) {
        return -1;
    }
    mgcp_parser->sdp_parser = NULL;
    return 0;
}

static struct parser *mgcp_parser_new(struct proto *proto)
{
    MALLOCER(mgcp_parsers);
    struct mgcp_parser *mgcp_parser = MALLOC(mgcp_parsers, sizeof(*mgcp_parser));
    if (! mgcp_parser) return NULL;

    if (-1 == mgcp_parser_ctor(mgcp_parser, proto)) {
        FREE(mgcp_parser);
        return NULL;
    }

    return &mgcp_parser->parser;
}

static void mgcp_parser_dtor(struct mgcp_parser *mgcp_parser)
{
    mgcp_parser->sdp_parser = parser_unref(mgcp_parser->sdp_parser);
    parser_dtor(&mgcp_parser->parser);
}

static void mgcp_parser_del(struct parser *parser)
{
    struct mgcp_parser *mgcp_parser = DOWNCAST(parser, parser, mgcp_parser);
    mgcp_parser_dtor(mgcp_parser);
    FREE(mgcp_parser);
}

/*
 * Proto Infos
 */

static char const *mgcp_command_2_str(enum mgcp_command command)
{
    switch (command) {
        case MGCP_EndpointConfiguration: return "EndpointConfiguration";
        case MGCP_CreateConnection:      return "CreateConnection";
        case MGCP_ModifyConnection:      return "ModifyConnection";
        case MGCP_DeleteConnection:      return "DeleteConnection";
        case MGCP_NotificationRequest:   return "NotificationRequest";
        case MGCP_Notify:                return "Notify";
        case MGCP_AuditEndpoint:         return "AuditEndpoint";
        case MGCP_AuditConnection:       return "AuditConnection";
        case MGCP_RestartInProgress:     return "RestartInProgress";
    }
    FAIL("Invalid MGCP command (%d)", command);
    return "INVALID";
}

static char const *mgcp_resp_2_str(struct mgcp_resp const *resp)
{
    char *str = tempstr_printf("code=%u, txid=%"PRI_MGCP_TXID, resp->code, resp->txid);
    return str;
}

static char const *mgcp_query_2_str(struct mgcp_query const *query)
{
    return tempstr_printf("command=%s, txid=%"PRI_MGCP_TXID", endpoint=%s",
        mgcp_command_2_str(query->command),
        query->txid, query->endpoint);
}

static char const *mgcp_events_2_str(unsigned events)
{
    return tempstr_printf("%s%s%s%s",
        events & MGCP_HD ? "l/hd,":"",
        events & MGCP_HU ? "l/hu,":"",
        events & MGCP_BZ ? "l/bz,":"",
        events & MGCP_RG ? "l/rg,":"");
}

static char const *mgcp_params_2_str(struct mgcp_proto_info const *info)
{
    return tempstr_printf("observed=%s signaled=%s %s%s%s%s%s%s",
        mgcp_events_2_str(info->observed),
        mgcp_events_2_str(info->signaled),
        info->dialed[0] != '\0' ? " dialed=":"",
        info->dialed[0] != '\0' ? info->dialed:"",
        info->cnx_id[0] != '\0' ? " cnxId=":"",
        info->cnx_id[0] != '\0' ? info->cnx_id:"",
        info->cnx_id[0] != '\0' ? " callId=":"",
        info->cnx_id[0] != '\0' ? info->call_id:"");
}

static void const *mgcp_info_addr(struct proto_info const *info_, size_t *size)
{
    struct mgcp_proto_info const *info = DOWNCAST(info_, info, mgcp_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *mgcp_info_2_str(struct proto_info const *info_)
{
    struct mgcp_proto_info const *info = DOWNCAST(info_, info, mgcp_proto_info);
    return tempstr_printf("%s, %s, %s",
        proto_info_2_str(info_),
        info->response ? mgcp_resp_2_str(&info->u.resp) : mgcp_query_2_str(&info->u.query),
        mgcp_params_2_str(info));
}

static void mgcp_serialize(struct proto_info const *info_, uint8_t **buf)
{
    struct mgcp_proto_info const *info = DOWNCAST(info_, info, mgcp_proto_info);
    proto_info_serialize(info_, buf);
    serialize_1(buf, info->response);
    if (info->response) {
        serialize_1(buf, info->u.resp.code);
        serialize_4(buf, info->u.resp.txid);
    } else {
        serialize_1(buf, info->u.query.command);
        serialize_4(buf, info->u.query.txid);
        serialize_str(buf, info->u.query.endpoint);
    }
    serialize_1(buf, info->observed);
    serialize_1(buf, info->signaled);
    serialize_str(buf, info->dialed);
    serialize_str(buf, info->cnx_id);
    serialize_str(buf, info->call_id);
}

static void mgcp_deserialize(struct proto_info *info_, uint8_t const **buf)
{
    struct mgcp_proto_info *info = DOWNCAST(info_, info, mgcp_proto_info);
    proto_info_deserialize(info_, buf);
    info->response = deserialize_1(buf);
    if (info->response) {
        info->u.resp.code = deserialize_1(buf);
        info->u.resp.txid = deserialize_4(buf);
    } else {
        info->u.query.command = deserialize_1(buf);
        info->u.query.txid = deserialize_4(buf);
        deserialize_str(buf, info->u.query.endpoint, sizeof(info->u.query.endpoint));
    }
    info->observed = deserialize_1(buf);
    info->signaled = deserialize_1(buf);
    deserialize_str(buf, info->dialed, sizeof(info->dialed));
    deserialize_str(buf, info->cnx_id, sizeof(info->cnx_id));
    deserialize_str(buf, info->call_id, sizeof(info->call_id));
}

static void mgcp_proto_info_ctor(struct mgcp_proto_info *info, struct parser *parser, struct proto_info *parent, size_t head_len, size_t payload)
{
    proto_info_ctor(&info->info, parser, parent, head_len, payload);
}

/*
 * Parse
 */

static enum mgcp_command mgcp_code_2_command(char const *code, size_t len)
{
#   define COMMAND_LEN 4
    static struct {
        char code[COMMAND_LEN+1];
        enum mgcp_command command;
    } verbs[] = {
        { "EPCF", MGCP_EndpointConfiguration },
        { "CRCX", MGCP_CreateConnection },
        { "MDCX", MGCP_ModifyConnection },
        { "DLCX", MGCP_DeleteConnection },
        { "RQNT", MGCP_NotificationRequest },
        { "NTFY", MGCP_Notify },
        { "AUEP", MGCP_AuditEndpoint },
        { "AUCX", MGCP_AuditConnection },
        { "RSIP", MGCP_RestartInProgress },
    };

    if (len < COMMAND_LEN) return (enum mgcp_command)-1;

    for (unsigned v = 0; v < NB_ELEMS(verbs); v++) {
        if (0 == strncasecmp(code, verbs[v].code, COMMAND_LEN)) return verbs[v].command;
    }

    return (enum mgcp_command)-1;
}

static struct liner_delimiter_set param_delims = {
    .nb_delims = 2,
    .delims = (struct liner_delimiter []){ { ", ", 2 }, { ",", 1 } },
    .collapse = true,
};

static struct mgcp_event {
    unsigned flag;
    char code[5];
    bool from_line;
} events[] = {
    { MGCP_HD, "l/hd", true }, { MGCP_HU, "l/hu", true }, { MGCP_BZ, "l/bz", true }, { MGCP_RG, "l/rg", true },
    { MGCP_FHD, "bp/hd", false }, { MGCP_FHU, "bp/hu", false },
};

unsigned parse_events(struct liner *liner)
{
    unsigned flags = 0;
    for (unsigned e = 0; e < NB_ELEMS(events); e++) {
        if (
            (liner_tok_length(liner) >= 4 && 0 == strncasecmp(liner->start, events[e].code, 4)) ||
            (events[e].from_line && (liner_tok_length(liner) >= 2 && 0 == strncasecmp(liner->start, events[e].code+2, 2)))
        ) {
            flags |= events[e].flag;
        }
    }
    return flags;
}

static void parse_observed_event(struct mgcp_proto_info *info, struct liner *liner)
{
    size_t len = strlen(info->dialed);
    struct liner tokenizer;
    for (
        liner_init(&tokenizer, &param_delims, liner->start, liner_tok_length(liner));
        ! liner_eof(&tokenizer);
        liner_next(&tokenizer)
    ) {
        unsigned events = parse_events(&tokenizer);
        if (events) {
            info->observed |= events;
            continue;
        }
        if (liner_tok_length(&tokenizer) < 3) continue;
        if (tokenizer.start[0] != 'D' && tokenizer.start[0] != 'd') continue;
        if (tokenizer.start[1] != '/') continue;
        // append dialed 'digit' into dialed info
        for (unsigned d = 2; d < liner_tok_length(&tokenizer); d++) {
            if (len >= sizeof(info->dialed)-1) break;
            char const c = tokenizer.start[d];
            if (c != 'T' && c != 't') info->dialed[len++] = c;
        }
    }
    assert(len < sizeof(info->dialed));
    info->dialed[len] = '\0';
}

static void parse_signal_request(struct mgcp_proto_info *info, struct liner *liner)
{
    struct liner tokenizer;
    for (
        liner_init(&tokenizer, &param_delims, liner->start, liner_tok_length(liner));
        ! liner_eof(&tokenizer);
        liner_next(&tokenizer)
    ) {
        info->signaled |= parse_events(&tokenizer);
    }
}

static void parse_connection_id(struct mgcp_proto_info *info, struct liner *liner)
{
    copy_token(info->cnx_id, sizeof(info->cnx_id), liner);
}

static void parse_call_id(struct mgcp_proto_info *info, struct liner *liner)
{
    copy_token(info->call_id, sizeof(info->call_id), liner);
}

// FIXME: give wire_len to liner ??
static enum proto_parse_status mgcp_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t unused_ wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct mgcp_parser *mgcp_parser = DOWNCAST(parser, parser, mgcp_parser);

    size_t payload = 0;
    // Parse one message (in case of piggybacking, will call ourself recursively so that subscribers are called once for each msg)
    struct mgcp_proto_info info;

    struct liner liner;
    liner_init(&liner, &delim_lines, (char const *)packet, cap_len);

    // Parse command, which is either verb + seq + endpoint + version or code + seq + blabla
    struct liner tokenizer;
    liner_init(&tokenizer, &delim_blanks, liner.start, liner_tok_length(&liner));
    if (liner_tok_length(&tokenizer) == 3 && isdigit(tokenizer.start[0])) {
        // Response
        info.response = true;
        info.u.resp.code = liner_strtoull(&tokenizer, NULL, 10);
        liner_next(&tokenizer);
        if (liner_eof(&tokenizer)) {
            SLOG(LOG_DEBUG, "Cannot parse MGCP response: missing TXID");
            return PROTO_PARSE_ERR;
        }
        info.u.resp.txid = liner_strtoull(&tokenizer, NULL, 10);
    } else {
        // Request
        info.response = false;
        info.u.query.command = mgcp_code_2_command(tokenizer.start, liner_tok_length(&tokenizer));
        if ((int)info.u.query.command == -1) return PROTO_PARSE_ERR;
        liner_next(&tokenizer);
        if (liner_eof(&tokenizer)) {
            SLOG(LOG_DEBUG, "Cannot parse MGCP query: missing TXID");
            return PROTO_PARSE_ERR;
        }
        info.u.resp.txid = liner_strtoull(&tokenizer, NULL, 10);
        liner_next(&tokenizer);
        if (liner_eof(&tokenizer)) {
            SLOG(LOG_DEBUG, "Cannot parse MGCP query: missing endpoint");
            return PROTO_PARSE_ERR;
        }
        copy_token(info.u.query.endpoint, sizeof(info.u.query.endpoint), &tokenizer);
    }
    liner_next(&liner);

    // Parse parameters up to end of msg or single dot
    struct parser *child = NULL;
    info.dialed[0] = '\0';
    info.cnx_id[0] = '\0';
    info.call_id[0] = '\0';
    info.observed = info.signaled = 0;

    while (! liner_eof(&liner)) {
        liner_init(&tokenizer, &delim_blanks, liner.start, liner_tok_length(&liner));
        liner_next(&liner);
        if (liner_tok_length(&tokenizer) == 0) {    // we met an empty line, assume following msg is SDP
            if (! mgcp_parser->sdp_parser) {
                mgcp_parser->sdp_parser = proto_sdp->ops->parser_new(proto_sdp);
            }
            child = mgcp_parser->sdp_parser;
            break;
        } else if (liner_tok_length(&tokenizer) == 1 && tokenizer.start[0] == '.') {
            break;
        } else if (liner_tok_length(&tokenizer) == 2 && tokenizer.start[1] == ':') {
            char p = tokenizer.start[0];
            liner_next(&tokenizer);
            if (liner_eof(&tokenizer)) {
                SLOG(LOG_DEBUG, "Cannot parse MGCP parameter '%c'", p);
                return PROTO_PARSE_ERR;
            }
            liner_expand(&tokenizer);
            SLOG(LOG_DEBUG, "parameter '%c'", p);
            switch (p) {
                case 'O':   // ObservedEvents: we are looking for dialed numbers or other interresting events
                    parse_observed_event(&info, &tokenizer);
                    break;
                case 'S':
                    parse_signal_request(&info, &tokenizer);
                    break;
                case 'I':
                    parse_connection_id(&info, &tokenizer);
                    break;
                case 'C':
                    parse_call_id(&info, &tokenizer);
                    break;
            }
        }
    }

    // End of message
    const size_t tot_len = liner.start - (char const *)packet;
    mgcp_proto_info_ctor(&info, parser, parent, tot_len - payload, payload);

    if (child) {
        // TODO: We suppose a call is unique in the socket pair, ie. that this parser will handle only one call, so we can keep our SDP with us.
        // SO, create a mgcp_parser with an embedded sdp parser, created as soon as mgcp_parser is constructed.
        size_t const rem_len = liner_rem_length(&liner);
        int err = proto_parse(child, &info.info, way, (uint8_t *)liner.start, rem_len, rem_len, now, tot_cap_len, tot_packet);
        if (err) proto_parse(NULL, &info.info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
        return PROTO_OK;
    }

    (void)proto_parse(NULL, &info.info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);

    // In case of piggybacking, we may have further messages down there
    if (! liner_eof(&liner)) {
        size_t const rem_len = liner_rem_length(&liner);
        return mgcp_parse(parser, parent, way, (uint8_t *)liner.start, rem_len, rem_len, now, tot_cap_len, tot_packet);
    }

    return PROTO_OK;
}

/*
 * Init
 */

static struct proto proto_mgcp_;
struct proto *proto_mgcp = &proto_mgcp_;
static struct port_muxer udp_port_muxer_gw, udp_port_muxer_agent;

void mgcp_init(void)
{
    log_category_proto_mgcp_init();

    static struct proto_ops const ops = {
        .parse       = mgcp_parse,
        .parser_new  = mgcp_parser_new,
        .parser_del  = mgcp_parser_del,
        .info_2_str  = mgcp_info_2_str,
        .info_addr   = mgcp_info_addr,
        .serialize   = mgcp_serialize,
        .deserialize = mgcp_deserialize,
    };
    proto_ctor(&proto_mgcp_, &ops, "MGCP", PROTO_CODE_MGCP);
    port_muxer_ctor(&udp_port_muxer_gw, &udp_port_muxers, 2427, 2427, proto_mgcp);
    port_muxer_ctor(&udp_port_muxer_agent, &udp_port_muxers, 2727, 2727, proto_mgcp);
}

void mgcp_fini(void)
{
    port_muxer_dtor(&udp_port_muxer_agent, &udp_port_muxers);
    port_muxer_dtor(&udp_port_muxer_gw, &udp_port_muxers);
    proto_dtor(&proto_mgcp_);
    log_category_proto_mgcp_fini();
}

