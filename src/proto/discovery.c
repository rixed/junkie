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
#include <stdbool.h>
#include <assert.h>
#include <inttypes.h>
#include "junkie/cpp.h"
#include "junkie/tools/ext.h"
#include "junkie/tools/log.h"
#include "junkie/tools/objalloc.h"
#include "junkie/netmatch.h"
#include "junkie/proto/serialize.h"
#include "junkie/proto/cnxtrack.h"
#include "junkie/proto/tcp.h"
#include "junkie/proto/udp.h"
#include "junkie/proto/discovery.h"

#undef LOG_CAT
#define LOG_CAT proto_discovery_log_category

LOG_CATEGORY_DEF(proto_discovery);

/*
 * Proto Infos
 */

static char const *discovery_trust_2_str(enum discovery_trust t)
{
    switch (t) {
        case DISC_HIGH:   return "high";
        case DISC_MEDIUM: return "medium";
        case DISC_LOW:    return "low";
    }
    assert(!"Invalid discovery_trust");
}

static void const *discovery_info_addr(struct proto_info const *info_, size_t *size)
{
    struct discovery_proto_info const *info = DOWNCAST(info_, info, discovery_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *discovery_info_2_str(struct proto_info const *info_)
{
    struct discovery_proto_info const *info = DOWNCAST(info_, info, discovery_proto_info);
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "%s, protocol=%u(%s), trust=%s",
        proto_info_2_str(info_),
        info->protocol.id, info->protocol.name,
        discovery_trust_2_str(info->protocol.trust));
    return str;
}

static void discovery_serialize(struct proto_info const *info_, uint8_t **buf)
{
    struct discovery_proto_info const *info = DOWNCAST(info_, info, discovery_proto_info);
    proto_info_serialize(info_, buf);
    serialize_1(buf, info->protocol.trust);
    serialize_2(buf, info->protocol.id);
    serialize_str(buf, info->protocol.name);
}

static void discovery_deserialize(struct proto_info *info_, uint8_t const **buf)
{
    struct discovery_proto_info *info = DOWNCAST(info_, info, discovery_proto_info);
    proto_info_deserialize(info_, buf);
    info->protocol.trust = deserialize_1(buf);
    info->protocol.id = deserialize_2(buf);
    deserialize_str(buf, info->protocol.name, sizeof(info->protocol.name));
}

/*
 * Proto signatures
 */

static LIST_HEAD(proto_signatures, proto_signature) proto_signatures;

struct proto_signature {
    LIST_ENTRY(proto_signature) entry;
    struct discovery_protocol protocol;
    struct netmatch_filter filter;
};

static int proto_signature_ctor(struct proto_signature *sig, uint16_t proto_id, char const *proto_name, enum discovery_trust trust, char const *filter_libname)
{
    SLOG(LOG_DEBUG, "Constructing proto_signature@%p", sig);
    sig->protocol.id = proto_id;
    sig->protocol.trust = trust;
    snprintf(sig->protocol.name, sizeof(sig->protocol.name), "%s", proto_name);
    if (0 != netmatch_filter_ctor(&sig->filter, filter_libname)) {
        return -1;
    }
    LIST_INSERT_HEAD(&proto_signatures, sig, entry);
    return 0;
}

static struct proto_signature *proto_signature_new(uint16_t proto_id, char const *proto_name, enum discovery_trust trust, char const *filter_libname)
{
    struct proto_signature *sig = objalloc(sizeof(*sig), "proto_signature");
    if (! sig) return NULL;
    if (0 != proto_signature_ctor(sig, proto_id, proto_name, trust, filter_libname)) {
        objfree(sig);
        return NULL;
    }
    return sig;
}

static void proto_signature_dtor(struct proto_signature *sig)
{
    SLOG(LOG_DEBUG, "Destructing proto_signature@%p", sig);
    LIST_REMOVE(sig, entry);
    netmatch_filter_dtor(&sig->filter);
}

static void proto_signature_del(struct proto_signature *sig)
{
    proto_signature_dtor(sig);
    objfree(sig);
}

static SCM high_sym, medium_sym, low_sym;

static SCM scm_from_trust(enum discovery_trust t)
{
    switch (t) {
        case DISC_HIGH:   return high_sym;
        case DISC_MEDIUM: return medium_sym;
        case DISC_LOW:    return low_sym;
    }
    assert(!"Invalid discovery_trust");
}


static struct ext_function sg_add_proto_signature;
static SCM g_add_proto_signature(SCM name_, SCM id_, SCM trust_, SCM filter_)
{
    scm_dynwind_begin(0);
    char *name = scm_to_locale_string(name_);
    scm_dynwind_free(name);

    unsigned id = scm_to_uint(id_);

    enum discovery_trust trust = DISC_LOW;
    if (scm_is_eq(trust_, high_sym)) {
        trust = DISC_HIGH;
    } else if (scm_is_eq(trust_, medium_sym)) {
        trust = DISC_MEDIUM;
    } else if (! scm_is_eq(trust_, low_sym)) {
        scm_throw(scm_from_latin1_symbol("no-such-trust"), scm_list_1(trust_));
    }

    char *libname = scm_to_locale_string(filter_);
    scm_dynwind_free(libname);

    struct proto_signature *sig = proto_signature_new(id, name, trust, libname);
    if (! sig) {
        scm_throw(scm_from_latin1_symbol("cannot-create-signature"), SCM_EOL);
    }

    scm_dynwind_end();
    return SCM_UNSPECIFIED;
}

static struct ext_function sg_proto_signatures;
static SCM g_proto_signatures(void)
{
    SCM ret = SCM_EOL;
    struct proto_signature *sig;
    LIST_FOREACH(sig, &proto_signatures, entry) ret = scm_cons(scm_from_locale_string(sig->protocol.name), ret);
    return ret;
}

static SCM proto_id_sym;
static SCM proto_trust_sym;
static SCM proto_libname_sym;

static struct ext_function sg_proto_signature_stats;
static SCM g_proto_signature_stats(SCM name_)
{
    char *name = scm_to_tempstr(name_);
    struct proto_signature *sig;
    LIST_LOOKUP(sig, &proto_signatures, entry, 0 == strcasecmp(sig->protocol.name, name));
    if (! sig) return SCM_UNSPECIFIED;

    return scm_list_3(
        scm_cons(proto_id_sym, scm_from_uint(sig->protocol.id)),
        scm_cons(proto_trust_sym, scm_from_trust(sig->protocol.trust)),
        scm_cons(proto_libname_sym, scm_from_latin1_string(sig->filter.libname)));
}


/*
 * Parse
 */

static enum proto_parse_status discovery_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    // iter on all filters until one matches
    struct proto_signature *sig;
    struct npc_register rest = { .size = cap_len, .value = (uintptr_t)packet };
    LIST_LOOKUP(sig, &proto_signatures, entry, 0 != sig->filter.match_fun(parent, rest, NULL, NULL));

    if (! sig) {
        (void)proto_parse(NULL, parent, way, packet, cap_len, wire_len, now, tot_cap_len, tot_packet);
        return PROTO_OK;
    }

    struct discovery_proto_info info;
    proto_info_ctor(&info.info, parser, parent, 0, wire_len);
    info.protocol = sig->protocol;

    (void)proto_parse(NULL, &info.info, way, packet, cap_len, wire_len, now, tot_cap_len, tot_packet);
    return PROTO_OK;
}

/*
 * Construction/Destruction
 */

static struct uniq_proto uniq_proto_discovery;
struct proto *proto_discovery = &uniq_proto_discovery.proto;
static struct port_muxer tcp_port_muxer;
static struct port_muxer udp_port_muxer;

void discovery_init(void)
{
    log_category_proto_discovery_init();
    LIST_INIT(&proto_signatures);

    static struct proto_ops const ops = {
        .parse       = discovery_parse,
        .parser_new  = uniq_parser_new,
        .parser_del  = uniq_parser_del,
        .info_2_str  = discovery_info_2_str,
        .info_addr   = discovery_info_addr,
        .serialize   = discovery_serialize,
        .deserialize = discovery_deserialize,
    };
    uniq_proto_ctor(&uniq_proto_discovery, &ops, "PIPI", PROTO_CODE_DISCOVERY);
    port_muxer_ctor(&tcp_port_muxer, &tcp_port_muxers, 1024, 65535, proto_discovery);
    port_muxer_ctor(&udp_port_muxer, &udp_port_muxers, 1024, 65535, proto_discovery);

	high_sym          = scm_permanent_object(scm_from_latin1_symbol("high"));
	medium_sym        = scm_permanent_object(scm_from_latin1_symbol("medium"));
	low_sym           = scm_permanent_object(scm_from_latin1_symbol("low"));
    proto_id_sym      = scm_permanent_object(scm_from_latin1_symbol("id"));
    proto_trust_sym   = scm_permanent_object(scm_from_latin1_symbol("trust"));
    proto_libname_sym = scm_permanent_object(scm_from_latin1_symbol("libname"));

    ext_function_ctor(&sg_add_proto_signature,
        "add-proto-signature", 4, 0, 0, g_add_proto_signature,  // TODO: additional optional parameter indicating what regular parser to run next
        "(add-proto-signature name id trust netmatch-filter): add this filter for given name/id with given trust level\n"
        "   trust can be either 'high, 'medium or 'low.\n"
        "   netmatch-filter is the name of a sofile containing a \"match\" function (as returned by netmatch compiler)\n");
    ext_function_ctor(&sg_proto_signatures,
        "proto-signatures", 0, 0, 0, g_proto_signatures,
        "(proto-signatures): list all currently defined protocol signatures.\n");
    ext_function_ctor(&sg_proto_signature_stats,
        "proto-signature-stats", 1, 0, 0, g_proto_signature_stats,
        "(proto-signature-stats name): display the definition and some stats about this signature.\n");
}

void discovery_fini(void)
{
    struct proto_signature *sig;
    while (NULL != (sig = LIST_FIRST(&proto_signatures))) {
        proto_signature_del(sig);
    }

    port_muxer_dtor(&udp_port_muxer, &udp_port_muxers);
    port_muxer_dtor(&tcp_port_muxer, &tcp_port_muxers);
    uniq_proto_dtor(&uniq_proto_discovery);
    log_category_proto_discovery_fini();
}
