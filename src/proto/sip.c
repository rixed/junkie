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
#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include "junkie/tools/objalloc.h"
#include "junkie/tools/log.h"
#include "junkie/tools/tempstr.h"
#include "junkie/tools/hash.h"
#include "junkie/tools/mutex.h"
#include "junkie/proto/ip.h"
#include "junkie/proto/tcp.h"
#include "junkie/proto/udp.h"
#include "junkie/proto/sdp.h"
#include "junkie/proto/sip.h"
#include "junkie/proto/cnxtrack.h"
#include "proto/liner.h"
#include "proto/httper.h"

#undef LOG_CAT
#define LOG_CAT proto_sip_log_category

LOG_CATEGORY_DEF(proto_sip);

#define SIP_PORT 5060
#define CALLID_TIMEOUT (1 * 60) // forget all about SDP messages for a callid after 1 minute (should be more than enough to receive infos for both directions)

/* Hash from SIP Call-id to SDP parser
 * (in order not to depend upon the transport socket pair as would be the case if SIP parser was a mux) */

struct callid_2_sdp {
    HASH_ENTRY(callid_2_sdp) entry;     // entry in the hash
    TAILQ_ENTRY(callid_2_sdp) used_entry;   // entry in the used list
    char call_id[SIP_CALLID_LEN+1];
    struct parser *sdp_parser;
    struct timeval last_used;
};

// The hash itself
static HASH_TABLE(callids_2_sdps, callid_2_sdp) callids_2_sdps;
// A list of all entries, in LRU order
static TAILQ_HEAD(callids_2_sdps_tq, callid_2_sdp) callids_2_sdps_used = TAILQ_HEAD_INITIALIZER(callids_2_sdps_used);
// A mutex to protect both the hash and the tailqueue
static struct mutex callids_2_sdps_mutex;

static void callid_2_sdp_dtor(struct callid_2_sdp *c2s)
{
    SLOG(LOG_DEBUG, "Destruct callid_2_sdp@%p for callid '%s'", c2s, c2s->call_id);
    HASH_REMOVE(&callids_2_sdps, c2s, entry);
    TAILQ_REMOVE(&callids_2_sdps_used, c2s, used_entry);
    parser_unref(&c2s->sdp_parser);
}

static void callid_2_sdp_del(struct callid_2_sdp *c2s)
{
    callid_2_sdp_dtor(c2s);
    objfree(c2s);
}

static void callids_2_sdps_timeout(struct timeval const *now)
{
    PTHREAD_ASSERT_LOCK(&callids_2_sdps_mutex.mutex);
    struct callid_2_sdp *c2s;
    while (NULL != (c2s = TAILQ_FIRST(&callids_2_sdps_used))) {
        if (likely_(timeval_sub(now, &c2s->last_used) <= CALLID_TIMEOUT * 1000000LL)) break;

        SLOG(LOG_DEBUG, "Timeouting callid_2_sdp@%p for callid '%s'", c2s, c2s->call_id);
        callid_2_sdp_del(c2s);
    }
}

static int callid_2_sdp_ctor(struct callid_2_sdp *c2s, char const *call_id, struct timeval const *now)
{
    SLOG(LOG_DEBUG, "Construct callid_2_sdp@%p for callid '%s'", c2s, call_id);
    c2s->sdp_parser = proto_sdp->ops->parser_new(proto_sdp);
    if (! c2s->sdp_parser) return -1;
    memset(c2s->call_id, 0, sizeof c2s->call_id); // because it's used as a hash key
    snprintf(c2s->call_id, sizeof(c2s->call_id), "%s", call_id);
    c2s->last_used = *now;
    mutex_lock(&callids_2_sdps_mutex);
    callids_2_sdps_timeout(now);
    HASH_INSERT(&callids_2_sdps, c2s, &c2s->call_id, entry);
    TAILQ_INSERT_TAIL(&callids_2_sdps_used, c2s, used_entry);
    mutex_unlock(&callids_2_sdps_mutex);
    return 0;
}

static struct callid_2_sdp *callid_2_sdp_new(char const *call_id, struct timeval const *now)
{
    struct callid_2_sdp *c2s = objalloc_nice(sizeof(*c2s), "SIP->SDP");
    if (! c2s) return NULL;
    if (0 != callid_2_sdp_ctor(c2s, call_id, now)) {
        objfree(c2s);
        return NULL;
    }
    return c2s;
}

static void callid_2_sdp_touch(struct callid_2_sdp *c2s, struct timeval const *now)
{
    mutex_lock(&callids_2_sdps_mutex);
    c2s->last_used = *now;
    TAILQ_REMOVE(&callids_2_sdps_used, c2s, used_entry);
    TAILQ_INSERT_TAIL(&callids_2_sdps_used, c2s, used_entry);
    mutex_unlock(&callids_2_sdps_mutex);
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
    info->content_length = liner_strtoull(liner, NULL, 10);
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
    memset(info->call_id, 0, sizeof info->call_id); // because it's used in HASH_LOOKUP
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

// The Via header may inform us that the peer is expecting answers on a non-standard port. Let's conntrack it.
static void conntrack_via(struct sip_proto_info const *info, struct timeval const *now)
{
    /* We conntrack the Via at every occurence, which will insert many conntrack
     * that will never be used (because most of the time Via is toward default SIP
     * port anyway.
     * We can't but hope that timeouting tracked connection will compensate for our
     * slopyness.
     * Notice that we conntrack from any peer to the Via address. SIP is so fun! */
    SLOG(LOG_DEBUG, "Conntracking SIP via %s %s:%"PRIu16,
        info->via.protocol == IPPROTO_UDP ? "UDP" :
            info->via.protocol == IPPROTO_TCP ? "TCP" : "unknown",
        ip_addr_2_str(&info->via.addr),
        info->via.port);

    assert(info->set_values & SIP_VIA_SET);
    (void)cnxtrack_ip_new(info->via.protocol, &info->via.addr, info->via.port, ADDR_UNKNOWN, PORT_UNKNOWN, false /* only one cnx */, proto_sip, now, NULL);
}

static enum proto_parse_status sip_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    static struct httper_command const commands[] = {
        [SIP_CMD_REGISTER] = { STRING_AND_LEN("REGISTER"), sip_set_command },
        [SIP_CMD_INVITE] =   { STRING_AND_LEN("INVITE"),   sip_set_command },
        [SIP_CMD_ACK] =      { STRING_AND_LEN("ACK"),      sip_set_command },
        [SIP_CMD_CANCEL] =   { STRING_AND_LEN("CANCEL"),   sip_set_command },
        [SIP_CMD_OPTIONS] =  { STRING_AND_LEN("OPTIONS"),  sip_set_command },
        [SIP_CMD_BYE] =      { STRING_AND_LEN("BYE"),      sip_set_command },
        [SIP_CMD_BYE+1] =    { STRING_AND_LEN("SIP/2.0"),  sip_set_response },
    };

    static struct httper_field const fields[] = {
        { STRING_AND_LEN("content-length"), sip_extract_content_length },
        { STRING_AND_LEN("content-type"),   sip_extract_content_type },
        { STRING_AND_LEN("cseq"),           sip_extract_cseq },
        { STRING_AND_LEN("call-id"),        sip_extract_callid },
        { STRING_AND_LEN("from"),           sip_extract_from },
        { STRING_AND_LEN("to"),             sip_extract_to },
        { STRING_AND_LEN("via"),            sip_extract_via },
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
    enum proto_parse_status status = httper_parse(&httper, &siphdr_len, packet, cap_len, &info);
    if (status != PROTO_OK) return PROTO_PARSE_ERR; // TODO: handle short packets with the help of a streambuf ?

    assert(siphdr_len <= cap_len);
    sip_proto_info_ctor(&info, parser, parent, siphdr_len, wire_len - siphdr_len);

    // If we are a request (with a Via), conntrack the Via path (if not already)
    if (
        (info.set_values & SIP_CMD_SET) &&
        (info.set_values & SIP_VIA_SET)
    ) {
        conntrack_via(&info, now);
    }

    struct parser *subparser = NULL;

#   define MIME_SDP "application/sdp"
    if (
        (info.set_values & SIP_CALLID_SET) &&
        (info.set_values & SIP_LENGTH_SET) &&
        info.content_length > 0 &&
        (info.set_values & SIP_MIME_SET) &&
        0 == strncasecmp(MIME_SDP, info.mime_type, strlen(MIME_SDP))
    ) {
        mutex_lock(&callids_2_sdps_mutex);
        // Maybe rehash the hash?
        static time_t last_rehash = 0; // timestamp (seconds) of the last rehash
        if (now->tv_sec > last_rehash) {
            last_rehash = now->tv_sec;
            HASH_TRY_REHASH(&callids_2_sdps, call_id, entry);
        }
        // Retrieve the global SDP for this call-id
        struct callid_2_sdp *c2s;
        SLOG(LOG_DEBUG, "Look for a callid_2_sdp for callid '%s'", info.call_id);
        HASH_LOOKUP(c2s, &callids_2_sdps, &info.call_id, call_id, entry);
        mutex_unlock(&callids_2_sdps_mutex);
        if (c2s) {
            SLOG(LOG_DEBUG, "Found a previous callid_2_sdp@%p", c2s);
            callid_2_sdp_touch(c2s, now);
        } else {
            c2s = callid_2_sdp_new(info.call_id, now);
        }
        if (c2s) subparser = c2s->sdp_parser;
    }
#   undef MIME_SDP

    if (! subparser) goto fallback;

    if (0 != proto_parse(subparser, &info.info, way, packet + siphdr_len, cap_len - siphdr_len, wire_len - siphdr_len, now, tot_cap_len, tot_packet)) goto fallback;
    return PROTO_OK;

fallback:
    (void)proto_parse(NULL, &info.info, way, packet + siphdr_len, cap_len - siphdr_len, wire_len - siphdr_len, now, tot_cap_len, tot_packet);
    return PROTO_OK;
}

/*
 * Init
 */

static struct uniq_proto uniq_proto_sip;
struct proto *proto_sip = &uniq_proto_sip.proto;
static struct port_muxer udp_port_muxer, tcp_port_muxer;

void sip_init(void)
{
    log_category_proto_sip_init();
    hash_init();
    mutex_ctor(&callids_2_sdps_mutex, "callids_2_sdps");
    HASH_INIT(&callids_2_sdps, 67, "SIP->SDP");

    static struct proto_ops const ops = {
        .parse       = sip_parse,
        .parser_new  = uniq_parser_new,
        .parser_del  = uniq_parser_del,
        .info_2_str  = sip_info_2_str,
        .info_addr   = sip_info_addr
    };
    uniq_proto_ctor(&uniq_proto_sip, &ops, "SIP", PROTO_CODE_SIP);
    port_muxer_ctor(&udp_port_muxer, &udp_port_muxers, SIP_PORT, SIP_PORT, proto_sip);
    port_muxer_ctor(&tcp_port_muxer, &tcp_port_muxers, SIP_PORT, SIP_PORT, proto_sip);
}

void sip_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    port_muxer_dtor(&tcp_port_muxer, &tcp_port_muxers);
    port_muxer_dtor(&udp_port_muxer, &udp_port_muxers);
    uniq_proto_dtor(&uniq_proto_sip);
    HASH_DEINIT(&callids_2_sdps);
    mutex_dtor(&callids_2_sdps_mutex);
#   endif
    log_category_proto_sip_fini();
    hash_fini();
}
