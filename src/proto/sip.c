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
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include <junkie/tools/mallocer.h>
#include <junkie/tools/log.h>
#include <junkie/tools/tempstr.h>
#include <junkie/proto/ip.h>
#include <junkie/proto/tcp.h>
#include <junkie/proto/udp.h>
#include <junkie/proto/sdp.h>
#include <junkie/proto/sip.h>
#include "proto/liner.h"
#include "proto/httper.h"

static char const Id[] = "$Id: de51c32f9992fe12b61752bf374468184b1a952d $";

#undef LOG_CAT
#define LOG_CAT proto_sip_log_category

LOG_CATEGORY_DEF(proto_sip);

#define SIP_TIMEOUT (60 * 5)
#define SIP_HASH_SIZE (100)
#define SIP_PORT 5060

/*
 * SIP parser
 */

static struct mux_proto mux_proto_sip;

struct sip_parser {
    struct sip_parser *dual;        // Our dual is the SIP parser that will handle the response (maybe ourself)
    struct mux_parser mux_parser;   // variable sized
};

static int sip_parser_ctor(struct sip_parser *sip_parser, struct proto *proto, struct timeval const *now)
{
    assert(proto == proto_sip);
    if (0 != mux_parser_ctor(&sip_parser->mux_parser, &mux_proto_sip, now)) {
        return -1;
    }

    sip_parser->dual = NULL;

    return 0;
}

static struct parser *sip_parser_new(struct proto *proto, struct timeval const *now)
{
    MALLOCER(sip_parsers);
    struct sip_parser *sip_parser = MALLOC(sip_parsers, sizeof(*sip_parser) - sizeof(sip_parser->mux_parser) + mux_parser_size(&mux_proto_sip));
    if (! sip_parser) return NULL;

    if (-1 == sip_parser_ctor(sip_parser, proto, now)) {
        FREE(sip_parser);
        return NULL;
    }

    return &sip_parser->mux_parser.parser;
}

static void sip_parser_dtor(struct sip_parser *sip_parser)
{
    if (sip_parser->dual) {
        if (sip_parser->dual != sip_parser) parser_unref(&sip_parser->dual->mux_parser.parser);
        sip_parser->dual = NULL;
    }
    mux_parser_dtor(&sip_parser->mux_parser);
}

static void sip_parser_del(struct parser *parser)
{
    struct mux_parser *mux_parser = DOWNCAST(parser, parser, mux_parser);
    struct sip_parser *sip_parser = DOWNCAST(mux_parser, mux_parser, sip_parser);
    sip_parser_dtor(sip_parser);
    FREE(sip_parser);
}

/*
 * Proto Infos
 */

char const *sip_cmd_2_str(enum sip_cmd_e cmd)
{
    switch (cmd) {
        case SIP_CMD_REGISTER: return "REGISTER";
        case SIP_CMD_INVITE:   return "INVITE";
        case SIP_CMD_ACK:      return "ACK";
        case SIP_CMD_CANCEL:   return "CANCEL";
        case SIP_CMD_OPTIONS:  return "OPTIONS";
        case SIP_CMD_BYE:      return "BYE";
    }
    FAIL("Invalid SIP command (%d)", cmd);
    return "INVALID";
}

static char const *via_protocol_2_str(unsigned protocol)
{
    switch (protocol) {
        case IPPROTO_UDP: return "UDP";
        case IPPROTO_TCP: return "TCP";
    }
    return "UNKNOWN";
}

static char const *via_2_str(struct sip_via const *via)
{
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "%s %s:%"PRIu16,
        via_protocol_2_str(via->protocol),
        ip_addr_2_str(&via->addr),
        via->port);
    return str;
}

static void const *sip_info_addr(struct proto_info const *info_, size_t *size)
{
    struct sip_proto_info const *info = DOWNCAST(info_, info, sip_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *sip_info_2_str(struct proto_info const *info_)
{
    struct sip_proto_info const *info = DOWNCAST(info_, info, sip_proto_info);
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "%s, cmd=%s, cseq=%s, via=%s, code=%s, mime_type=%s, content-length=%s, call-id=%s, from=%s, to=%s",
             proto_info_2_str(info_),
             info->set_values & SIP_CMD_SET    ? sip_cmd_2_str(info->cmd)          : "unset",
             info->set_values & SIP_CSEQ_SET   ? tempstr_printf("%lu", info->cseq) : "unset",
             info->set_values & SIP_VIA_SET    ? via_2_str(&info->via)             : "unset",
             info->set_values & SIP_CODE_SET   ? tempstr_printf("%u", info->code)  : "unset",
             info->set_values & SIP_MIME_SET   ? info->mime_type                   : "unset",
             info->set_values & SIP_LENGTH_SET ? tempstr_printf("%u", info->content_length) : "unset",
             info->set_values & SIP_CALLID_SET ? info->call_id                     : "unset",
             info->set_values & SIP_FROM_SET   ? info->from                        : "unset",
             info->set_values & SIP_TO_SET     ? info->to                          : "unset");

    return str;
}

static void sip_proto_info_ctor(struct sip_proto_info *info, struct parser *parser, struct proto_info *parent, size_t head_len, size_t payload)
{
    proto_info_ctor(&info->info, parser, parent, head_len, payload);
}

/*
 * Parse
 */

static int sip_set_command(unsigned cmd, struct liner unused_ *liner, void *info_)
{
    struct sip_proto_info *info = info_;
    info->set_values |= SIP_CMD_SET;
    info->cmd = cmd;
    return 0;
}

static int sip_set_response(unsigned unused_ cmd, struct liner *liner, void *info_)
{
    struct sip_proto_info *info = info_;
    info->set_values |= SIP_CODE_SET;
    info->code = liner_strtoull(liner, NULL, 10);
    return 0;
}

static int sip_extract_cseq(unsigned unused_ cmd, struct liner *liner, void *info_)
{
    struct sip_proto_info *info = info_;
    info->cseq = liner_strtoull(liner, NULL, 10);
    info->set_values |= SIP_CSEQ_SET;
    return 0;
}

static int sip_extract_content_length(unsigned unused_ field, struct liner *liner, void *info_)
{
    struct sip_proto_info *info = info_;
    info->set_values |= SIP_LENGTH_SET;
    info->content_length = strtoull(liner->start, NULL, 10);
    return 0;
}

static int sip_extract_content_type(unsigned unused_ field, struct liner *liner, void *info_)
{
    struct sip_proto_info *info = info_;
    info->set_values |= SIP_MIME_SET;
    copy_token(info->mime_type, sizeof(info->mime_type), liner);
    return 0;
}

static int sip_extract_callid(unsigned unused_ field, struct liner *liner, void *info_)
{
    struct sip_proto_info *info = info_;
    info->set_values |= SIP_CALLID_SET;
    copy_token(info->call_id, sizeof info->call_id, liner);
    return 0;
}

static int sip_extract_from(unsigned unused_ field, struct liner *liner, void *info_)
{
    struct sip_proto_info *info = info_;
    info->set_values |= SIP_FROM_SET;
    copy_token(info->from, sizeof info->from, liner);
    return 0;
}

static int sip_extract_to(unsigned unused_ field, struct liner *liner, void *info_)
{
    struct sip_proto_info *info = info_;
    info->set_values |= SIP_TO_SET;
    copy_token(info->to, sizeof info->to, liner);
    return 0;
}

static int sip_extract_via(unsigned unused_ field, struct liner *liner, void *info_)
{
    struct sip_proto_info *info = info_;

    // We are interrested only in the first Via stanza
    if (info->set_values & SIP_VIA_SET) return 0;

    // We are parsing something like : SIP/2.0/UDP 123.456.789.123:12345;foo=bar etc
    struct liner spacer;
    liner_init(&spacer, &delim_blanks, liner->start, liner_tok_length(liner));

    // Extract IP protocol
#   define SIP_VER "SIP/2.0/"
    if (liner_tok_length(&spacer) < strlen(SIP_VER) + 3) {
        SLOG(LOG_DEBUG, "Via token too short (%.*s)", (int)liner_tok_length(&spacer), spacer.start);
        return 0;
    }
    char const *proto_str = spacer.start + strlen(SIP_VER);
    if (0 == strncasecmp(proto_str, "UDP", 3)) {
        info->via.protocol = IPPROTO_UDP;
    } else if (0 == strncasecmp(proto_str, "TCP", 3)) {
        info->via.protocol = IPPROTO_TCP;
    } else {
        SLOG(LOG_DEBUG, "Via protocol unknown (%.*s)", 3, proto_str);
        return 0;
    }

    // Extract IP
    liner_next(&spacer);
    struct liner semicoloner;   // first get IP:port or IP
    liner_init(&semicoloner, &delim_semicolons, spacer.start, liner_tok_length(&spacer));
    struct liner coloner;   // then only IP and then port
    liner_init(&coloner, &delim_colons, semicoloner.start, liner_tok_length(&semicoloner));
    if (0 != ip_addr_ctor_from_str(&info->via.addr, coloner.start, liner_tok_length(&coloner), 4)) {    // FIXME: ip_addr_ctor_from_str should detect IP version
        SLOG(LOG_DEBUG, "Cannot extract IP addr from Via string (%.*s)",
            (int)liner_tok_length(&coloner), coloner.start);
        return 0;
    }

    // Extract Port
    liner_next(&coloner);
    if (liner_eof(&coloner)) {   // no port specified
        SLOG(LOG_DEBUG, "No port specified in Via string, assuming "STRIZE(SIP_PORT));
        info->via.port = SIP_PORT;
    } else {    // port is present
        char const *end;
        info->via.port = liner_strtoull(&coloner, &end, 10);
        if (end == coloner.start) {
            SLOG(LOG_DEBUG, "Cannot extract IP port from Via string (%.*s)",
                (int)liner_tok_length(&coloner), coloner.start);
            return 0;
        }
    }

    info->set_values |= SIP_VIA_SET;
    return 0;
}

static void try_create_dual(struct sip_parser *sip_parser, struct sip_proto_info const *info, struct proto_info *parent, unsigned way, struct timeval const *now)
{
    unsigned server_port = 0;
    struct proto *proto_transp;
    struct proto_info const *info_transp;
    if (info->via.protocol == IPPROTO_UDP) {
        ASSIGN_INFO_CHK(udp, parent, );
        server_port = udp->key.port[!way];  // packet is going from client to server, so we want port[1] (dest), if not inversed
        info_transp = &udp->info;
        proto_transp = proto_udp;
    } else {
        ASSIGN_INFO_CHK(tcp, parent, );
        server_port = tcp->key.port[!way];
        info_transp = &tcp->info;
        proto_transp = proto_tcp;
    }
    ASSIGN_INFO_CHK(ip, info_transp, );

    // Look for a transp parser between the server (ip->addr[!way]:server_port), and
    // the client address specified in Via field (info->via.addr:info->via.port)
    unsigned way2;
    struct mux_subparser *ip_subparser =
        ip_subparser_lookup(ip->info.parser, proto_transp, NULL, info->via.protocol, ip->key.addr+!way, &info->via.addr, &way2, now);
    // Then for the SIP parser, child of this transp (UDP|TCP) parser
    if (! ip_subparser) return;
    struct mux_subparser *transp_subparser =
        (info->via.protocol == IPPROTO_UDP ? udp_subparser_lookup : tcp_subparser_lookup)
        (ip_subparser->parser, proto_sip, NULL, server_port, info->via.port, way2, now);

    if (! transp_subparser) return;
    assert(transp_subparser->parser->proto == proto_sip);

    // Store the returned ref
    assert(! sip_parser->dual);
    struct parser *const dual_parser = transp_subparser->parser;
    if (transp_subparser->parser != &sip_parser->mux_parser.parser) parser_ref(transp_subparser->parser);   // avoid stupid loop

    sip_parser->dual = DOWNCAST(DOWNCAST(dual_parser, parser, mux_parser), mux_parser, sip_parser);
}

static enum proto_parse_status sip_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t unused_ *okfn, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct mux_parser *mux_parser = DOWNCAST(parser, parser, mux_parser);
    struct sip_parser *sip_parser = DOWNCAST(mux_parser, mux_parser, sip_parser);

    static struct httper_command const commands[] = {
        [SIP_CMD_REGISTER] = { "REGISTER", 8, sip_set_command },
        [SIP_CMD_INVITE] =   { "INVITE",   6, sip_set_command },
        [SIP_CMD_ACK] =      { "ACK",      3, sip_set_command },
        [SIP_CMD_CANCEL] =   { "CANCEL",   6, sip_set_command },
        [SIP_CMD_OPTIONS] =  { "OPTIONS",  7, sip_set_command },
        [SIP_CMD_BYE] =      { "BYE",      3, sip_set_command },
        [SIP_CMD_BYE+1] =    { "SIP/2.0",  7, sip_set_response },
    };

    static struct httper_field const fields[] = {
        { "content-length", 14, sip_extract_content_length },
        { "content-type",   12, sip_extract_content_type },
        { "cseq",           4,  sip_extract_cseq },
        { "call-id",        7,  sip_extract_callid },
        { "from",           4,  sip_extract_from },
        { "to",             2,  sip_extract_to },
        { "via",            3,  sip_extract_via },
    };

    static struct httper const httper = {
        .nb_commands = NB_ELEMS(commands),
        .commands = commands,
        .nb_fields = NB_ELEMS(fields),
        .fields = fields
    };

    SLOG(LOG_DEBUG, "Starting SIP analysis");

    /* Parse */

    struct sip_proto_info info;
    info.set_values = 0;

    size_t siphdr_len;
    if (0 != httper_parse(&httper, &siphdr_len, packet, cap_len, &info)) return PROTO_PARSE_ERR;

    assert(siphdr_len <= cap_len);
    sip_proto_info_ctor(&info, parser, parent, siphdr_len, wire_len - siphdr_len);

    // If we are a request (with a Via), without our dual, then create it
    if (
        (info.set_values & SIP_CMD_SET) &&
        (info.set_values & SIP_VIA_SET) &&
        !sip_parser->dual
    ) {
        try_create_dual(sip_parser, &info, parent, way, now);
    }

    struct mux_subparser *subparser = NULL;

#define MIME_SDP "application/sdp"
    if (
        (info.set_values & SIP_LENGTH_SET) &&
        info.content_length > 0 &&
        (info.set_values & SIP_MIME_SET) &&
        0 == strncasecmp(MIME_SDP, info.mime_type, strlen(MIME_SDP))
    ) {
        subparser = mux_subparser_lookup(mux_parser, proto_sdp, parser, &info.cseq, now);
        if (sip_parser->dual && sip_parser->dual != sip_parser) {
            SLOG(LOG_DEBUG, "Make our dual @%p use the same SDP parser for CSeq %lu", sip_parser->dual, info.cseq);
            // Notice: Whenever sip subparsers are no longer mere mux_subparsers, retrieve the mux_proto.ops.subparser_new
            mux_subparser_new(&sip_parser->dual->mux_parser, subparser->parser, parser, &info.cseq);
        }
    }
#undef MIME_SDP

    if (! subparser) goto fallback;

    if (0 != proto_parse(subparser->parser, &info.info, way, packet + siphdr_len, cap_len - siphdr_len, wire_len - siphdr_len, now, okfn, tot_cap_len, tot_packet)) goto fallback;
    return PROTO_OK;

fallback:
    (void)proto_parse(NULL, &info.info, way, packet + siphdr_len, cap_len - siphdr_len, wire_len - siphdr_len, now, okfn, tot_cap_len, tot_packet);
    return PROTO_OK;
}

/*
 * Init
 */

struct proto *proto_sip = &mux_proto_sip.proto;
static struct port_muxer udp_port_muxer;

void sip_init(void)
{
    // check the variable size of struc sip_parser
    CHECK_LAST_FIELD(sip_parser, mux_parser, struct mux_parser);

    log_category_proto_sip_init();

    static struct proto_ops const ops = {
        .parse      = sip_parse,
        .parser_new = sip_parser_new,
        .parser_del = sip_parser_del,
        .info_2_str = sip_info_2_str,
        .info_addr  = sip_info_addr,
    };
    mux_proto_ctor(&mux_proto_sip, &ops, &mux_proto_ops, "SIP", SIP_TIMEOUT, sizeof (unsigned long), SIP_HASH_SIZE);
    port_muxer_ctor(&udp_port_muxer, &udp_port_muxers, SIP_PORT, SIP_PORT, proto_sip);
}

void sip_fini(void)
{
    port_muxer_dtor(&udp_port_muxer, &udp_port_muxers);
    mux_proto_dtor(&mux_proto_sip);
    log_category_proto_sip_fini();
}
