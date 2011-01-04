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
#include <inttypes.h>
#include <assert.h>
#include <string.h>
#include <junkie/cpp.h>
#include <junkie/ext.h>
#include <junkie/tools/mallocer.h>
#include <junkie/tools/tempstr.h>
#include <junkie/tools/hash.h>
#include <junkie/tools/timeval.h>
#include <junkie/tools/jhash.h>
#include <junkie/proto/proto.h>
#include "proto/fuzzing.h"

static char const Id[] = "$Id: 177ba6f85a03ac706a2bade616ed149d9394784d $";

static unsigned nb_fuzzed_bits = 0;
EXT_PARAM_RW(nb_fuzzed_bits, "nb-fuzzed-bits", uint, "Max number of bits to fuzz by protocolar layer (0 to disable fuzzing).")

#undef LOG_CAT
#define LOG_CAT proto_log_category

LOG_CATEGORY_DEC(proto);
LOG_CATEGORY_DEF(proto);

struct protos protos;

char const *parser_name(struct parser const *parser)
{
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "%s@%p", parser->proto->name, parser);
    return str;
}

void proto_ctor(
    struct proto *proto,            ///< The proto to construct
    struct proto_ops const *ops,    ///< The ops structure of this implementation
    char const *name,               ///< A name for the proto
    unsigned timeout                ///< Any parser unused after that long will be killed with no mercy
)
{
    SLOG(LOG_DEBUG, "Constructing proto %s", name);

    proto->ops = ops;
    proto->name = name;
    proto->nb_frames = 0;
    proto->nb_bytes = 0;
    proto->timeout = timeout;
    proto->fuzzed_times = 0;
    TAILQ_INIT(&proto->parsers);
    proto->nb_parsers = 0;
    LIST_INSERT_HEAD(&protos, proto, entry);

    mutex_ctor_with_type(&proto->lock, name, PTHREAD_MUTEX_RECURSIVE);
}

static void make_alive(struct parser *parser)
{
    mutex_lock(&parser->proto->lock);
    TAILQ_INSERT_TAIL(&parser->proto->parsers, parser, proto_entry);
    parser->proto->nb_parsers ++;
    parser->alive = true;
    mutex_unlock(&parser->proto->lock);
    parser_ref(parser);
}

static void remove_alive(struct parser *parser)
{
    mutex_lock(&parser->proto->lock);
    TAILQ_REMOVE(&parser->proto->parsers, parser, proto_entry);
    parser->proto->nb_parsers --;
    parser->alive = false;
    mutex_unlock(&parser->proto->lock);
    parser_unref(parser);
}

void proto_dtor(struct proto *proto)
{
    SLOG(LOG_DEBUG, "Destructing proto %s", proto->name);

    struct parser *parser;
    while (NULL != (parser = TAILQ_FIRST(&proto->parsers))) {
        SLOG(LOG_DEBUG, "Unref instance of this proto @%p", parser);
        assert(parser->proto == proto);
        remove_alive(parser);
    }
    assert(TAILQ_EMPTY(&proto->parsers));

    LIST_REMOVE(proto, entry);
    mutex_dtor(&proto->lock);
}

unsigned proto_timeout(struct timeval const *now)
{
    unsigned nb_victims = 0;

    struct proto *proto;
    LIST_FOREACH(proto, &protos, entry) {
        mutex_lock(&proto->lock);
        if (proto->timeout > 0) {
            int64_t timeout = proto->timeout * 1000000;
            struct parser *parser;
            while (NULL != (parser = TAILQ_FIRST(&proto->parsers))) {
                // As parsers are sorted by last_used time (least recently used first),
                // we can stop scanning as soon as we met a survivor.
                if (likely_(timeval_sub(now, &parser->last_used) <= timeout)) break;

                SLOG(LOG_DEBUG, "Timeouting parser %s", parser_name(parser));
                assert(parser->proto == proto);
                assert(parser->alive);
                remove_alive(parser);
                nb_victims ++;
            }
        }
        mutex_unlock(&proto->lock);
    }

    return nb_victims;
}

struct proto *proto_of_name(char const *name)
{
    struct proto *proto;
    LIST_FOREACH(proto, &protos, entry) {
        if (0 == strcasecmp(proto->name, name)) {
            return proto;
        }
    }
    return NULL;
}

enum proto_parse_status proto_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn)
{
    assert(cap_len <= wire_len);

    if (! parser) {
        if (okfn) (void)okfn(parent);
        return PROTO_OK;   // This is not a parse error if okfn fails.
    }

    mutex_lock(&parser->proto->lock);
    parser->proto->nb_frames ++;
    parser->proto->nb_bytes += wire_len;
    mutex_unlock(&parser->proto->lock);
    // Promote at list end since it's used
    parser->last_used = *now;
    if (unlikely_(! parser->alive)) {
        make_alive(parser);
    } else {
        mutex_lock(&parser->proto->lock);
        TAILQ_REMOVE(&parser->proto->parsers, parser, proto_entry);
        TAILQ_INSERT_TAIL(&parser->proto->parsers, parser, proto_entry);
        mutex_unlock(&parser->proto->lock);
    }

    SLOG(LOG_DEBUG, "Parse packet @%p, size %zu (%zu captured), #%"PRIu64" for %s",
        packet, wire_len, cap_len, parser->proto->nb_frames, parser_name(parser));

    if (unlikely_(nb_fuzzed_bits > 0)) fuzz(parser, packet, cap_len, nb_fuzzed_bits);

    enum proto_parse_status ret = parser->proto->ops->parse(parser, parent, way, packet, cap_len, wire_len, now, okfn);
    if (ret == PROTO_TOO_SHORT) {
        // We are missing some informations but we've done as much as possible.
        if (okfn) (void)okfn(parent);
        return PROTO_OK;   // This is not a parse error if okfn fails.
    }
    return ret;
}

/*
 * Proto Infos
 */

struct proto_info const *proto_info_get(struct proto const *proto, struct proto_info const *last)
{
    while (last) {
        if (last->parser->proto == proto) return last;
        last = last->parent;
    }

    return NULL;
}

void proto_info_ctor(struct proto_info *info, struct parser *parser, struct proto_info *parent, size_t head_len, size_t payload)
{
    info->parent = parent;
    info->parser = parser;
    info->head_len = head_len;
    info->payload = payload;
}

void const *proto_info_addr(struct proto_info const *info, size_t *size)
{
    if (size) *size = sizeof(*info);
    return info;
}

char const *proto_info_2_str(struct proto_info const *info)
{
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "head_len=%zu, payload=%zu", info->head_len, info->payload);
    return str;
}

/*
 * Parsers
 */

int parser_ctor(struct parser *parser, struct proto *proto, struct timeval const *now)
{
    assert(proto);
    parser->proto = proto;
    SLOG(LOG_DEBUG, "Constructing parser %s", parser_name(parser));

    parser->last_used = *now;

    parser->ref_count = 1;  // for the caller
    make_alive(parser);

    return 0;
}

static struct parser *parser_new(struct proto *proto, struct timeval const *now)
{
    MALLOCER(parsers);
    struct parser *parser = MALLOC(parsers, sizeof(*parser));
    if (unlikely_(! parser)) return NULL;

    if (unlikely_(0 != parser_ctor(parser, proto, now))) {
        FREE(parser);
        return NULL;
    }

    return parser;
}

void parser_dtor(struct parser *parser)
{
    SLOG(LOG_DEBUG, "Destructing parser %s", parser_name(parser));
    assert(! parser->alive);
    assert(parser->ref_count == 0);
    assert(parser->proto);
}

static void parser_del(struct parser *parser)
{
    parser_dtor(parser);
    FREE(parser);
}

struct parser *parser_ref(struct parser *parser)
{
    if (! parser) return NULL;
    SLOG(LOG_DEBUG, "refing %s", parser_name(parser));

    assert(parser->ref_count > 0);  // or where this ref could come from ?
    parser->ref_count ++;
    return parser;
}

struct parser *parser_unref(struct parser *parser)
{
    if (! parser) return NULL;
    SLOG(LOG_DEBUG, "unrefing %s", parser_name(parser));

    assert(parser->ref_count > 0);
    parser->ref_count --;

    if (parser->ref_count == 0) {
        SLOG(LOG_DEBUG, "deleting %s", parser_name(parser));
        parser->proto->ops->parser_del(parser);
        return NULL;
    }

    if (parser->ref_count == 1 && parser->alive) {  // Don't wait until timeout
        remove_alive(parser);
        return NULL;
    }

    return NULL;
}

/*
 * Dummy proto
 */

static enum proto_parse_status dummy_parse(struct parser unused_ *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn)
{
    return proto_parse(NULL, parent, way, packet, cap_len, wire_len, now, okfn);
}

static struct proto static_proto_dummy;
struct proto *proto_dummy = &static_proto_dummy;

static void dummy_init(void)
{
    static struct proto_ops const ops = {
        .parse      = dummy_parse,
        .parser_new = parser_new,
        .parser_del = parser_del,
    };
    proto_ctor(&static_proto_dummy, &ops, "Dummy", 0);
}

static void dummy_fini(void)
{
    proto_dtor(&static_proto_dummy);
}

/*
 * Multiplexers
 *
 * Helpers for parsers that are multiplexers
 */

// List of all mux_protos used to configure them from Guile
static LIST_HEAD(mux_protos, mux_proto) mux_protos = LIST_HEAD_INITIALIZER(&mux_protos);

void mux_subparser_dtor(struct mux_subparser *subparser)
{
    assert(subparser->mux_parser->nb_children > 0);
    subparser->parser = parser_unref(subparser->parser);

    // As we avoid taking a reference to "ourself", we also avoid unrefing in this case
    subparser->requestor = subparser->requestor != subparser->parser ?
        parser_unref(subparser->requestor) : NULL;

    LIST_REMOVE(subparser, h_entry);

    if (subparser->doomed) {
        LIST_REMOVE(subparser, doom_entry);
        subparser->doomed = false;
    }

    subparser->mux_parser->nb_children --;
}

void mux_subparser_del(struct mux_subparser *subparser)
{
    mux_subparser_dtor(subparser);
    FREE(subparser);
}

static bool nb_children_ok(struct mux_parser *mux_parser)
{
    return
        mux_parser->nb_max_children == 0 ||
        mux_parser->nb_children < mux_parser->nb_max_children;
}

static struct mutex doomed_mutex;
static LIST_HEAD(doomed_subparsers, mux_subparser) doomed_subparsers;

void mux_subparser_doom(struct mux_subparser *subparser)
{
    if (subparser->doomed) return;

    mutex_lock(&doomed_mutex);

    LIST_INSERT_HEAD(&doomed_subparsers, subparser, doom_entry);
    subparser->doomed = true;

    mutex_unlock(&doomed_mutex);
}

void mux_subparser_kill_doomed(void)
{
    mutex_lock(&doomed_mutex);

    struct mux_subparser *subparser;
    while (NULL != (subparser = LIST_FIRST(&doomed_subparsers))) {
        struct mux_proto *mux_proto = DOWNCAST(subparser->mux_parser->parser.proto, proto, mux_proto);
        mux_proto->ops.subparser_del(subparser);
    }

    mutex_unlock(&doomed_mutex);
}

static void sacrifice_child(struct mux_parser *mux_parser)
{
    struct mux_proto *mux_proto = DOWNCAST(mux_parser->parser.proto, proto, mux_proto);

    // Kill one at "random"
    static unsigned hh = 0;
    hh ++;
    for (unsigned h = hh % mux_parser->hash_size; h < mux_parser->hash_size; h++) {
        struct mux_subparser *subparser = LIST_FIRST(mux_parser->subparsers+h);
        if (! subparser) continue;
        SLOG(LOG_DEBUG, "Too many children for mux %s, killing %p", parser_name(&mux_parser->parser), subparser);
        mux_subparser_doom(subparser);
        mux_proto->nb_infanticide ++;
        return;
    }
}

static unsigned hash_key(void const *key, size_t key_sz, unsigned hash_sz)
{
#   define ANY_VALUE 0x432317F5U
    return hashlittle(key, key_sz, ANY_VALUE) % hash_sz;
}

int mux_subparser_ctor(struct mux_subparser *subparser, struct mux_parser *mux_parser, struct parser *child, struct parser *requestor, void const *key)
{
    assert(child);
    SLOG(LOG_DEBUG, "Construct mux_subparser@%p for parser %s requested by %s", subparser, parser_name(child), requestor ? parser_name(requestor) : "nobody");

    if (! nb_children_ok(mux_parser)) sacrifice_child(mux_parser);

    subparser->parser = parser_ref(child);
    subparser->requestor = parser_ref(requestor);
    subparser->mux_parser = mux_parser;
    subparser->doomed = false;

    struct mux_proto *mux_proto = DOWNCAST(mux_parser->parser.proto, proto, mux_proto);
    unsigned h = hash_key(key, mux_proto->key_size, mux_parser->hash_size);
    LIST_INSERT_HEAD(mux_parser->subparsers+h, subparser, h_entry);
    mux_parser->nb_children ++;
    memcpy(subparser->key, key, mux_proto->key_size);
    return 0;
}

void *mux_subparser_alloc(struct mux_parser *mux_parser, size_t size_without_key)
{
    MALLOCER(mux_subparsers);
    struct mux_proto *mux_proto = DOWNCAST(mux_parser->parser.proto, proto, mux_proto);
    void *subparser = MALLOC(mux_subparsers, size_without_key + mux_proto->key_size);
    return subparser;
}

// Creates the subparser _and_ the parser
struct mux_subparser *mux_subparser_new(struct mux_parser *mux_parser, struct parser *child, struct parser *requestor, void const *key)
{
    struct mux_subparser *subparser = mux_subparser_alloc(mux_parser, sizeof(*subparser));
    if (unlikely_(! subparser)) return NULL;

    if (0 != mux_subparser_ctor(subparser, mux_parser, child, requestor, key)) {
        FREE(subparser);
        return NULL;
    }

    return subparser;
}

struct mux_subparser *mux_subparser_and_parser_new(struct mux_parser *mux_parser, struct proto *proto, struct parser *requestor, void const *key, struct timeval const *now)
{
    struct parser *child = proto->ops->parser_new(proto, now);
    if (unlikely_(! child)) return NULL;

    struct mux_proto *mux_proto = DOWNCAST(mux_parser->parser.proto, proto, mux_proto);
    struct mux_subparser *subparser = mux_proto->ops.subparser_new(mux_parser, child, requestor, key);
    if (unlikely_(! subparser)) {
        child->proto->ops->parser_del(child);
    }

    parser_unref(child);    // No need to keep this anymore

    return subparser;
}

struct mux_subparser *mux_subparser_lookup(struct mux_parser *mux_parser, struct proto *create_proto, struct parser *requestor, void const *key, struct timeval const *now)
{
    struct mux_proto *mux_proto = DOWNCAST(mux_parser->parser.proto, proto, mux_proto);
    unsigned h = hash_key(key, mux_proto->key_size, mux_parser->hash_size);

    unsigned nb_colls = 0;
    struct mux_subparser *subparser, *tmp;
    LIST_FOREACH_SAFE(subparser, mux_parser->subparsers+h, h_entry, tmp) {
        if (! subparser->parser->alive) {
            mux_subparser_doom(subparser);
            continue;
        }
        if (
            (!create_proto || subparser->parser->proto == create_proto) &&
            0 == memcmp(subparser->key, key, mux_proto->key_size)
        ) {
            break;
        }
        nb_colls ++;
    }

    if (subparser && nb_colls > 2) {
        // Promote this children to the head of the list to retrieve it faster next time
        LIST_REMOVE(subparser, h_entry);
        LIST_INSERT_HEAD(mux_parser->subparsers+h, subparser, h_entry);
    }

    if (nb_colls > 8) {
        SLOG(nb_colls > 100 ? LOG_NOTICE : LOG_DEBUG, "%u collisions while looking for supparser of %s", nb_colls, mux_parser->parser.proto->name);
        if (unlikely_(nb_colls > 100)) {
            SLOG(LOG_NOTICE, "Dump of first keys for h = %u :", h);
            struct mux_subparser *s;
            unsigned limit = 5;
            LIST_FOREACH(s, mux_parser->subparsers+h, h_entry) {
                SLOG_HEX(LOG_NOTICE, s->key, mux_proto->key_size);
                if (limit-- == 0) break;
            }
        }
    }

    mux_proto->nb_lookups ++;
    mux_proto->nb_collisions += nb_colls;

    if (subparser || ! create_proto) return subparser;

    // Create a new one
    return mux_subparser_and_parser_new(mux_parser, create_proto, requestor, key, now);
}

void mux_subparser_change_key(struct mux_subparser *subparser, struct mux_parser *mux_parser, void const *key)
{
    SLOG(LOG_DEBUG, "changing key for subparser @%p", subparser);

    // Remove
    LIST_REMOVE(subparser, h_entry);
    // Change key
    struct mux_proto *mux_proto = DOWNCAST(mux_parser->parser.proto, proto, mux_proto);
    memcpy(subparser->key, key, mux_proto->key_size);
    // Re-insert
    unsigned h = hash_key(key, mux_proto->key_size, mux_parser->hash_size);
    LIST_INSERT_HEAD(mux_parser->subparsers+h, subparser, h_entry);
}

int mux_parser_ctor(struct mux_parser *mux_parser, struct mux_proto *mux_proto, struct timeval const *now)
{
    if (unlikely_(0 != parser_ctor(&mux_parser->parser, &mux_proto->proto, now))) return -1;

    mux_parser->hash_size = mux_proto->hash_size;   // We start with this size of hash
    for (unsigned h = 0; h < mux_proto->hash_size; h++) {
        LIST_INIT(mux_parser->subparsers+h);
    }

    mux_parser->nb_children = 0;
    mux_parser->nb_max_children = mux_proto->nb_max_children;   // we copy it since the user may want to change this value for future mux_parsers

    return 0;
}

size_t mux_parser_size(struct mux_proto *mux_proto)
{
    struct mux_parser unused_ mux_parser;   // for the following sizeofs
    return sizeof(mux_parser) + mux_proto->hash_size * sizeof(*mux_parser.subparsers);
}

struct parser *mux_parser_new(struct proto *proto, struct timeval const *now)
{
    MALLOCER(mux_protos);
    struct mux_proto *mux_proto = DOWNCAST(proto, proto, mux_proto);
    struct mux_parser *mux_parser = MALLOC(mux_protos, mux_parser_size(mux_proto));
    if (unlikely_(! mux_parser)) return NULL;

    if (unlikely_(0 != mux_parser_ctor(mux_parser, mux_proto, now))) {
        FREE(mux_parser);
        return NULL;
    }

    return &mux_parser->parser;
}

void mux_parser_dtor(struct mux_parser *mux_parser)
{
    // We are going to delete our users. Since we are destructing, we should have ref_count=0.
    assert(mux_parser->parser.ref_count == 0);
    // So, none of our child can delete us
    struct mux_proto *mux_proto = DOWNCAST(mux_parser->parser.proto, proto, mux_proto);

    // Delete all children (here there is not much choice than to delete for real)
    for (unsigned h = 0; h < mux_parser->hash_size; h++) {
        struct mux_subparser *subparser;
        while (NULL != (subparser = LIST_FIRST(mux_parser->subparsers+h))) {
            mux_proto->ops.subparser_del(subparser);
        }
    }

    // Then ancestor parser
    parser_dtor(&mux_parser->parser);
}

void mux_parser_del(struct parser *parser)
{
    struct mux_parser *mux_parser = DOWNCAST(parser, parser, mux_parser);
    mux_parser_dtor(mux_parser);
    FREE(mux_parser);
}

void mux_proto_ctor(struct mux_proto *mux_proto, struct proto_ops const *ops, struct mux_proto_ops const *mux_ops, char const *name, unsigned timeout, size_t key_size, unsigned hash_size)
{
    proto_ctor(&mux_proto->proto, ops, name, timeout);
    mux_proto->ops = *mux_ops;
    mux_proto->hash_size = hash_size;
    mux_proto->key_size = key_size;
    mux_proto->nb_max_children = 0;
    mux_proto->nb_infanticide = 0;
    mux_proto->nb_collisions = 0;
    mux_proto->nb_lookups = 0;
    LIST_INSERT_HEAD(&mux_protos, mux_proto, entry);
}

void mux_proto_dtor(struct mux_proto *mux_proto)
{
    LIST_REMOVE(mux_proto, entry);
    proto_dtor(&mux_proto->proto);
}

struct mux_proto_ops mux_proto_ops = {
    .subparser_new = mux_subparser_new,
    .subparser_del = mux_subparser_del,
};

/*
 * Helper for stateless parsers
 */

void uniq_proto_ctor(struct uniq_proto *uniq_proto, struct proto_ops const *ops, char const *name)
{
    proto_ctor(&uniq_proto->proto, ops, name, 0);
    uniq_proto->parser = NULL;
}

void uniq_proto_dtor(struct uniq_proto *uniq_proto)
{
    uniq_proto->parser = parser_unref(uniq_proto->parser);
    proto_dtor(&uniq_proto->proto);
}

struct parser *uniq_parser_new(struct proto *proto, struct timeval const *now)
{
    struct uniq_proto *uniq_proto = DOWNCAST(proto, proto, uniq_proto);
    mutex_lock(&proto->lock);
    if (! uniq_proto->parser) {
        uniq_proto->parser = parser_new(proto, now);
    }
    mutex_unlock(&proto->lock);

    SLOG(LOG_DEBUG, "New user for uniq parser %s", parser_name(uniq_proto->parser));

    return parser_ref(uniq_proto->parser);
}

void uniq_parser_del(struct parser *parser)
{
    struct uniq_proto *uniq_proto = DOWNCAST(parser->proto, proto, uniq_proto);
    assert(uniq_proto->parser == NULL || uniq_proto->parser == parser); // the ref is already unrefed but the pointer itself must be undergoing NULLing
    FREE(parser);
}

/*
 * Extensions
 */

static struct ext_function sg_proto_names;
static SCM g_proto_names(void)
{
    SCM ret = SCM_EOL;
    struct proto *proto;
    LIST_FOREACH(proto, &protos, entry) ret = scm_cons(scm_from_locale_string(proto->name), ret);
    return ret;
}

struct proto *proto_of_scm_name(SCM name_)
{
    char *name = scm_to_tempstr(name_);
    return proto_of_name(name);
}

static struct ext_function sg_mux_proto_names;
static SCM g_mux_proto_names(void)
{
    SCM ret = SCM_EOL;
    struct mux_proto *mux_proto;
    LIST_FOREACH(mux_proto, &mux_protos, entry) ret = scm_cons(scm_from_locale_string(mux_proto->proto.name), ret);
    return ret;
}

static struct mux_proto *mux_proto_of_scm_name(SCM name_)
{
    char *name = scm_to_tempstr(name_);
    struct mux_proto *mux_proto;
    LIST_FOREACH(mux_proto, &mux_protos, entry) {
        if (0 == strcasecmp(name, mux_proto->proto.name)) return mux_proto;
    }
    return NULL;
}

static struct ext_function sg_mux_proto_stats;
static SCM g_mux_proto_stats(SCM name_)
{
    struct mux_proto *mux_proto = mux_proto_of_scm_name(name_);
    if (! mux_proto) return SCM_UNSPECIFIED;

    SCM alist = scm_list_n(
        scm_cons(scm_from_locale_symbol("hash-size"),       scm_from_uint(mux_proto->hash_size)),
        scm_cons(scm_from_locale_symbol("nb-max-children"), scm_from_uint(mux_proto->nb_max_children)),
        scm_cons(scm_from_locale_symbol("nb-infanticide"),  scm_from_uint(mux_proto->nb_infanticide)),
        scm_cons(scm_from_locale_symbol("nb-collisions"),   scm_from_uint64(mux_proto->nb_collisions)),
        scm_cons(scm_from_locale_symbol("nb-lookups"),      scm_from_uint64(mux_proto->nb_lookups)),
        SCM_UNDEFINED);
    return alist;
}

static struct ext_function sg_proto_stats;
static SCM g_proto_stats(SCM name_)
{
    struct proto *proto = proto_of_scm_name(name_);
    if (! proto) return SCM_UNSPECIFIED;

    return scm_list_n(
        // We use scm_from_locale_symbol a lot : hopefully the symbol will always be the same.
        // Maybe we could/should build the symbol once at init time, but I'm not sure symbols are not garbage collected.
        // So we should also declare a permanent ref on them ?
        scm_cons(scm_from_locale_symbol("nb-frames"),  scm_from_int64(proto->nb_frames)),
        scm_cons(scm_from_locale_symbol("nb-bytes"),   scm_from_int64(proto->nb_bytes)),
        scm_cons(scm_from_locale_symbol("nb-parsers"), scm_from_uint(proto->nb_parsers)),
        scm_cons(scm_from_locale_symbol("nb-fuzzed"),  scm_from_uint(proto->fuzzed_times)),
        scm_cons(scm_from_locale_symbol("timeout"),    scm_from_uint(proto->timeout)),
        SCM_UNDEFINED);
}

static struct ext_function sg_proto_set_timeout;
static SCM g_proto_set_timeout(SCM name_, SCM timeout_)
{
    struct proto *proto = proto_of_scm_name(name_);
    if (! proto) return SCM_UNSPECIFIED;

    unsigned const timeout = scm_to_uint(timeout_);
    mutex_lock(&proto->lock);
    proto->timeout = timeout;
    mutex_unlock(&proto->lock);

    return SCM_BOOL_T;
}

static struct ext_function sg_mux_proto_set_max_children;
static SCM g_mux_proto_set_max_children(SCM name_, SCM nb_max_children_)
{
    struct mux_proto *mux_proto = mux_proto_of_scm_name(name_);
    if (! mux_proto) return SCM_UNSPECIFIED;

    unsigned const nb_max_children = scm_to_uint(nb_max_children_); // beware : don't take the lock before scm_to_uint() which can raise an exception
    mutex_lock(&mux_proto->proto.lock);
    mux_proto->nb_max_children = nb_max_children;
    mutex_unlock(&mux_proto->proto.lock);

    return SCM_BOOL_T;
}

static struct ext_function sg_mux_proto_set_hash_size;
static SCM g_mux_proto_set_hash_size(SCM name_, SCM hash_size_)
{
    struct mux_proto *mux_proto = mux_proto_of_scm_name(name_);
    if (! mux_proto) return SCM_UNSPECIFIED;

    unsigned const hash_size = scm_to_uint(hash_size_);
    mutex_lock(&mux_proto->proto.lock);
    mux_proto->hash_size = hash_size;
    mux_proto->nb_collisions = 0;
    mux_proto->nb_lookups = 0;
    mutex_unlock(&mux_proto->proto.lock);

    return SCM_BOOL_T;
}

void proto_init(void)
{
    log_category_proto_init();
    mutex_ctor(&doomed_mutex, "doomed mux_subparsers");
    LIST_INIT(&doomed_subparsers);
    ext_param_nb_fuzzed_bits_init();

    ext_function_ctor(&sg_proto_stats,
        "proto-stats", 1, 0, 0, g_proto_stats,
        "(proto-stats \"proto-name\") : returns some statistics about this protocolar parser, such as number of instances.\n"
        "See also (? 'proto-names) for a list of protocol names.\n");

    ext_function_ctor(&sg_proto_names,
        "proto-names", 0, 0, 0, g_proto_names,
        "(proto-names) : returns the list of availbale protocol names.\n");

    ext_function_ctor(&sg_mux_proto_names,
        "mux-names", 0, 0, 0, g_mux_proto_names,
        "(mux-names) : returns the list of availbale protocol names that are multiplexers.\n");

    ext_function_ctor(&sg_mux_proto_stats,
        "mux-stats", 1, 0, 0, g_mux_proto_stats,
        "(mux-stats \"proto-name\") : returns various stats about this multiplexer.\n"
        "See also (? 'mux-names) for a list of protocol names that are multiplexers.\n"
        "         (? 'set-max-children) and (? 'set-mux-hash-size) for altering a multiplexer.\n");

    ext_function_ctor(&sg_mux_proto_set_max_children,
        "set-max-children", 2, 0, 0, g_mux_proto_set_max_children,
        "(set-max-children \"proto-name\" n) : limits the number of children of each parser of this protocol to n.\n"
        "Once n is reached, a child is killed at random.\n"
        "If n is 0, then there is no such limit.\n"
        "See also (? 'mux-names) for a list of protocol names that are multiplexers.\n");

    ext_function_ctor(&sg_mux_proto_set_hash_size,
        "set-mux-hash-size", 2, 0, 0, g_mux_proto_set_hash_size,
        "(set-mux-hash-size \"proto-name\" n) : sets the hash size for newly created parsers of this protocol.\n"
        "Beware of max allowed childrens whenever you change this value.\n"
        "See also (? 'set-max-children) for setting the max number of allowed child for newly created parsers of a protocol.\n"
        "         (? 'mux-names) for a list of protocol names that are multiplexers.\n");

    ext_function_ctor(&sg_proto_set_timeout,
        "set-proto-timeout", 1, 0, 0, g_proto_set_timeout,
        "(set-proto-timeout \"proto-name\" n) : sets the number of seconds after which an unused parser for this proto is reclaimed.\n"
        "A value of 0 disable timeouting of these parsers.\n"
        "See also (? 'proto-names) for a list of availbale protocol names,\n"
        "         (? 'proto-stats) for obtaining the current value.\n");

    dummy_init();
}

void proto_fini(void)
{
    mux_subparser_kill_doomed();
    dummy_fini();
    mutex_dtor(&doomed_mutex);
    ext_param_nb_fuzzed_bits_fini();
    log_category_proto_fini();
}
