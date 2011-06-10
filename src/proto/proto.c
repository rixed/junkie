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
#include <junkie/tools/ext.h>
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

static unsigned mux_timeout = 120;
EXT_PARAM_RW(mux_timeout, "mux-timeout", uint, "After how many seconds an unused multiplexer subparser may be deleted.")

#undef LOG_CAT
#define LOG_CAT proto_log_category

LOG_CATEGORY_DEF(proto);

struct protos protos;

char const *parser_name(struct parser const *parser)
{
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "%s@%p", parser->proto->name, parser);
    return str;
}

void proto_ctor(struct proto *proto, struct proto_ops const *ops, char const *name)
{
    SLOG(LOG_DEBUG, "Constructing proto %s", name);

    proto->ops = ops;
    proto->name = name;
    proto->nb_frames = 0;
    proto->nb_bytes = 0;
    proto->fuzzed_times = 0;
    proto->nb_parsers = 0;
    LIST_INSERT_HEAD(&protos, proto, entry);

    mutex_ctor_with_type(&proto->lock, name, PTHREAD_MUTEX_RECURSIVE);
}

static void add_to_proto(struct parser *parser)
{
#   ifdef __GNUC__
    (void)__sync_add_and_fetch(&parser->proto->nb_parsers, 1);
#   else
    mutex_lock(&parser->proto->lock);
    parser->proto->nb_parsers ++;
    mutex_unlock(&parser->proto->lock);
#   endif
}

static void remove_from_proto(struct parser *parser)
{
#   ifdef __GNUC__
    (void)__sync_sub_and_fetch(&parser->proto->nb_parsers, 1);
#   else
    mutex_lock(&parser->proto->lock);
    parser->proto->nb_parsers --;
    mutex_unlock(&parser->proto->lock);
#   endif
#   ifndef NDEBUG
#   define POISON ((void*)3)
    parser->proto = POISON;
#   endif
}

void proto_dtor(struct proto *proto)
{
    SLOG(LOG_DEBUG, "Destructing proto %s", proto->name);
#   if 0
    assert(proto->nb_parsers == 0);
#   endif
    LIST_REMOVE(proto, entry);
    mutex_dtor(&proto->lock);
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

enum proto_parse_status proto_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn, size_t tot_cap_len, uint8_t const *tot_packet)
{
    assert(cap_len <= wire_len);

    if (! parser) {
        if (okfn) (void)okfn(parent, tot_cap_len, tot_packet);
        return PROTO_OK;   // This is not a parse error if okfn fails.
    }

#   ifdef __GNUC__
    (void)__sync_add_and_fetch(&parser->proto->nb_frames, 1);
    (void)__sync_add_and_fetch(&parser->proto->nb_bytes, wire_len);
#   else
    mutex_lock(&parser->proto->lock);
    parser->proto->nb_frames ++;
    parser->proto->nb_bytes += wire_len;
    mutex_unlock(&parser->proto->lock);
#   endif

    SLOG(LOG_DEBUG, "Parse packet @%p, size %zu (%zu captured), #%"PRIu64" for %s",
        packet, wire_len, cap_len, parser->proto->nb_frames, parser_name(parser));

    if (unlikely_(nb_fuzzed_bits > 0)) fuzz(parser, packet, cap_len, nb_fuzzed_bits);

    enum proto_parse_status ret = parser->proto->ops->parse(parser, parent, way, packet, cap_len, wire_len, now, okfn, tot_cap_len, tot_packet);

    if (ret == PROTO_TOO_SHORT) {
        SLOG(LOG_DEBUG, "Too short for parser %s", parser_name(parser));
        // We are missing some informations but we've done as much as possible.
        if (okfn) (void)okfn(parent, tot_cap_len, tot_packet);
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

static void parser_del_as_ref(struct ref *ref)
{
    struct parser *const parser = DOWNCAST(ref, ref, parser);
    SLOG(LOG_DEBUG, "Deleting parser %s", parser_name(parser));
    parser->proto->ops->parser_del(parser);
}

int parser_ctor(struct parser *parser, struct proto *proto)
{
    assert(proto);
    parser->proto = proto;
    SLOG(LOG_DEBUG, "Constructing parser %s", parser_name(parser));
    ref_ctor(&parser->ref, parser_del_as_ref);
    add_to_proto(parser);

    return 0;
}

static struct parser *parser_new(struct proto *proto)
{
    MALLOCER(parsers);
    struct parser *parser = MALLOC(parsers, sizeof(*parser));
    if (unlikely_(! parser)) return NULL;

    if (unlikely_(0 != parser_ctor(parser, proto))) {
        FREE(parser);
        return NULL;
    }

    return parser;
}

void parser_dtor(struct parser *parser)
{
    SLOG(LOG_DEBUG, "Destructing parser %s", parser_name(parser));
    remove_from_proto(parser);
    ref_dtor(&parser->ref);
}

static void parser_del(struct parser *parser)
{
    parser_dtor(parser);
    FREE(parser);
}

struct parser *parser_ref(struct parser *parser)
{
    if (parser) SLOG(LOG_DEBUG, "ref parser %s count=%u", parser_name(parser), parser->ref.count+1);
    return DOWNCAST(ref(&parser->ref), ref, parser);
}

struct parser *parser_unref(struct parser *parser)
{
    if (parser) SLOG(LOG_DEBUG, "unref parser %s count=%u", parser_name(parser), parser->ref.count-1);
    return DOWNCAST(unref(&parser->ref), ref, parser);
}

/*
 * Dummy proto
 */

static enum proto_parse_status dummy_parse(struct parser unused_ *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn, size_t tot_cap_len, uint8_t const *tot_packet)
{
    return proto_parse(NULL, parent, way, packet, cap_len, wire_len, now, okfn, tot_cap_len, tot_packet);
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
    proto_ctor(&static_proto_dummy, &ops, "Dummy");
}

static void dummy_fini(void)
{
    proto_dtor(&static_proto_dummy);
}

/*
 * Multiplexers
 *
 * Helpers for parsers that are multiplexers
 *
 * mux_parsers must be usable concurrently, so we must have different mutexes for different subparsers.
 * But having a mutex per hash line takes too much memory, so we share a pool of mutexes in the mux_proto.
 */

char const *mux_subparser_name(struct mux_subparser const *subparser)
{
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "mux_subparser@%p for parser %s", subparser, parser_name(subparser->parser));
    return str;
}

static struct subparsers *list_of_h_idx(struct mux_parser *mux_parser, unsigned h_idx)
{
    return mux_parser->subparsers + h_idx;
}

static struct subparsers *list_of_subparser_(struct mux_subparser *subparser, unsigned h_idx)
{
    return list_of_h_idx(subparser->mux_parser, h_idx);
}

static struct subparsers *list_of_subparser(struct mux_subparser *subparser)
{
    assert(subparser->h_idx != NOT_HASHED);
    return list_of_subparser_(subparser, subparser->h_idx);
}

static struct mutex *mutex_of_h_idx(struct mux_parser *mux_parser, unsigned h_idx)
{
    struct mux_proto *mux_proto = DOWNCAST(mux_parser->parser.proto, proto, mux_proto);
    return mux_proto->mutexes + ((h_idx + (intptr_t)mux_parser) % NB_ELEMS(mux_proto->mutexes));
}

static struct mutex *mutex_of_subparser_(struct mux_subparser *subparser, unsigned h_idx)
{
    return mutex_of_h_idx(subparser->mux_parser, h_idx);
}
static struct mutex *mutex_of_subparser(struct mux_subparser *subparser)
{
    assert(subparser->h_idx != NOT_HASHED);
    return mutex_of_subparser_(subparser, subparser->h_idx);
}

// List of all mux_protos used to configure them from Guile
static LIST_HEAD(mux_protos, mux_proto) mux_protos = LIST_HEAD_INITIALIZER(mux_protos);

// Caller must own list->mutex
static void mux_subparser_deindex_locked(struct mux_subparser *subparser)
{
    struct subparsers *list = list_of_subparser(subparser);
#   ifdef __GNUC__
    unsigned const unused_ n = __sync_fetch_and_sub(&subparser->mux_parser->nb_children, 1);
    assert(n > 0);
#   else
    subparser->mux_parser->nb_children --;  // better not take this too seriously then (we do not lock mux_parser because of possible deadlock)
#   endif
    TAILQ_REMOVE(&list->list, subparser, entry);
    subparser->h_idx = NOT_HASHED;
    (void)unref(&subparser->ref);
}

void mux_subparser_deindex(struct mux_subparser *subparser)
{
    unsigned h_idx;
    struct mutex *mutex;

    do {
        h_idx = subparser->h_idx;
        if (h_idx == NOT_HASHED) return;
        mutex = mutex_of_subparser_(subparser, h_idx);

        mutex_lock(mutex);
        // by the time the lock is acquired maybe another thread changed subparser->h_idx?
        if (h_idx == (unsigned volatile)subparser->h_idx) break;
        SLOG(LOG_WARNING, "Subparser list changed while waiting for list mutex");
        mutex_unlock(mutex);
    } while (1);

    mux_subparser_deindex_locked(subparser);

    mutex_unlock(mutex);
}

// Caller must own subparsers mutex
static void mux_subparser_index(struct mux_subparser *subparser)
{
    struct subparsers *list = list_of_subparser(subparser);
    TAILQ_INSERT_TAIL(&list->list, subparser, entry);
#   if __GNUC__
    (void)__sync_fetch_and_add(&subparser->mux_parser->nb_children, 1);
#   else
    subparser->mux_parser->nb_children ++;
#   endif
    (void)ref(&subparser->ref);
}

void mux_subparser_dtor(struct mux_subparser *subparser)
{
    SLOG(LOG_DEBUG, "Destructing mux_subparser@%p", subparser);
    subparser->parser = parser_unref(subparser->parser);
    ref_dtor(&subparser->ref);
#   ifndef NDEBUG
    subparser->mux_parser = POISON;
#   endif
}

void mux_subparser_del(struct mux_subparser *subparser)
{
    mux_subparser_dtor(subparser);
    FREE(subparser);
}

// Caller must own subparsers mutex
static bool too_many_children(struct mux_parser *mux_parser)
{
    return
        mux_parser->nb_max_children != 0 &&
        mux_parser->nb_children > mux_parser->nb_max_children;
}

// Caller must own list->mutex
static void try_sacrifice_child(struct mux_proto *mux_proto, struct subparsers *list)
{
    if (TAILQ_EMPTY(&list->list)) return;
    struct mux_subparser *subparser = TAILQ_LAST(&list->list, mux_subparsers);

    SLOG(LOG_DEBUG, "Too many children, killing %s", mux_subparser_name(subparser));

    mux_subparser_deindex_locked(subparser);

#   ifdef __GNUC__
    (void)__sync_add_and_fetch(&mux_proto->nb_infanticide, 1);
#   else
    mutex_lock(&mux_proto->proto.lock);
    mux_proto->nb_infanticide ++
    mutex_unlock(&mux_proto->proto.lock);
#   endif
}

static unsigned hash_key(void const *key, size_t key_sz, unsigned hash_size)
{
#   define ANY_VALUE 0x432317F5U
    return hashlittle(key, key_sz, ANY_VALUE) % hash_size;
}

// Caller must own list->mutex
static void mux_subparsers_timeout(struct mux_proto *mux_proto, struct mux_subparsers *list, unsigned timeout_s, struct timeval const *now)
{
    if (0 == timeout_s) return;

    // Beware that deletion of a subparser can lead to the creation of new parsers !
    int64_t const timeout = timeout_s * 1000000LL;
    struct mux_subparser *subparser;
    unsigned count = 0;
    while (NULL != (subparser = TAILQ_FIRST(list))) {
        // As parsers are sorted by last_used time (least recently used first),
        // we can stop scanning as soon as we met a survivor.
        if (likely_(timeval_sub(now, &subparser->last_used) <= timeout)) break;

        SLOG(LOG_DEBUG, "Timeouting subparser %s", mux_subparser_name(subparser));
        mux_subparser_deindex_locked(subparser);

        count ++;
    }

#   ifdef __GNUC__
    (void)__sync_add_and_fetch(&mux_proto->nb_timeouts, count);
#   else    // well, don't put to much trust in this then
    mux_proto->nb_timeouts += count;
#   endif
}

static void mux_subparser_del_as_ref(struct ref *ref)
{
    struct mux_subparser *subparser = DOWNCAST(ref, ref, mux_subparser);
    // Beware that subparser->mux_parser might have been deleted already, so we need a backlink to mux_proto
    subparser->mux_proto->ops.subparser_del(subparser);
}

int mux_subparser_ctor(struct mux_subparser *subparser, struct mux_parser *mux_parser, struct parser *child, struct proto *requestor, void const *key, struct timeval const *now)
{
    assert(child);
    struct mux_proto *mux_proto = DOWNCAST(mux_parser->parser.proto, proto, mux_proto);
    SLOG(LOG_DEBUG, "Construct mux_subparser@%p for parser %s requested by %s", subparser, parser_name(child), requestor ? requestor->name : "nobody");

    subparser->parser = parser_ref(child);
    subparser->requestor = requestor;
    subparser->mux_parser = mux_parser; // backlink
    subparser->mux_proto = mux_proto;   // another backlink, see mux_subparser_del_as_ref().
    subparser->last_used = *now;
    memcpy(subparser->key, key, mux_proto->key_size);
    ref_ctor(&subparser->ref, mux_subparser_del_as_ref);

    subparser->h_idx = hash_key(key, mux_proto->key_size, mux_parser->hash_size);
    struct mutex *mutex = mutex_of_subparser(subparser);
    struct subparsers *list = list_of_subparser(subparser);

    mutex_lock(mutex);

    mux_subparsers_timeout(mux_proto, &list->list, mux_timeout, now);
    if (too_many_children(mux_parser)) {
        try_sacrifice_child(mux_proto, list);
    }

    mux_subparser_index(subparser);

    mutex_unlock(mutex);

    return 0;
}

void *mux_subparser_alloc(struct mux_parser *mux_parser, size_t size_without_key)
{
    MALLOCER(mux_subparsers);
    struct mux_proto *mux_proto = DOWNCAST(mux_parser->parser.proto, proto, mux_proto);
    void *subparser = MALLOC(mux_subparsers, size_without_key + mux_proto->key_size);
    return subparser;
}

// Creates the subparser _and_ the parser, returns a ref on the subparser
struct mux_subparser *mux_subparser_new(struct mux_parser *mux_parser, struct parser *child, struct proto *requestor, void const *key, struct timeval const *now)
{
    struct mux_subparser *subparser = mux_subparser_alloc(mux_parser, sizeof(*subparser));
    if (unlikely_(! subparser)) return NULL;

    if (0 != mux_subparser_ctor(subparser, mux_parser, child, requestor, key, now)) {
        FREE(subparser);
        return NULL;
    }

    return subparser;
}

struct mux_subparser *mux_subparser_ref(struct mux_subparser *subparser)
{
    return ref(&subparser->ref);
}

struct mux_subparser *mux_subparser_unref(struct mux_subparser *subparser)
{
    return unref(&subparser->ref);
}

struct mux_subparser *mux_subparser_and_parser_new(struct mux_parser *mux_parser, struct proto *proto, struct proto *requestor, void const *key, struct timeval const *now)
{
    struct parser *child = proto->ops->parser_new(proto);
    if (unlikely_(! child)) return NULL;

    struct mux_proto *mux_proto = DOWNCAST(mux_parser->parser.proto, proto, mux_proto);
    struct mux_subparser *subparser = mux_proto->ops.subparser_new(mux_parser, child, requestor, key, now);
    parser_unref(child);    // whatever the outcome, no need to keep this anymore

    return subparser;
}

struct mux_subparser *mux_subparser_lookup(struct mux_parser *mux_parser, struct proto *create_proto, struct proto *requestor, void const *key, struct timeval const *now)
{
    struct mux_proto *mux_proto = DOWNCAST(mux_parser->parser.proto, proto, mux_proto);
    unsigned h = hash_key(key, mux_proto->key_size, mux_parser->hash_size);
    struct mutex *mutex = mutex_of_h_idx(mux_parser, h);
    struct subparsers *list = list_of_h_idx(mux_parser, h);

    mutex_lock(mutex);

    unsigned nb_colls = 0;
    struct mux_subparser *subparser;
    TAILQ_FOREACH(subparser, &list->list, entry) {
        if (
            // FIXME: various kind of subparsers might have the same key so we should include proto in any case,
            // whether or not we intend to create the child if not found (ie. use another flag for that).
            // But we cannot do that actually, because in case of contracking we want to find whatever the proto
            // registered the ports.
            (!create_proto || subparser->parser->proto == create_proto) &&
            0 == memcmp(subparser->key, key, mux_proto->key_size)
        ) {
            break;
        }
        nb_colls ++;
    }

    if (subparser && now) {
        // Promote this children to the tail of the list since it is used
        subparser->last_used = *now;
        TAILQ_REMOVE(&list->list, subparser, entry);
        TAILQ_INSERT_TAIL(&list->list, subparser, entry);
    }

    if (nb_colls > 8) {
        SLOG(nb_colls > 100 ? LOG_NOTICE : LOG_DEBUG, "%u collisions while looking for subparser of %s", nb_colls, mux_parser->parser.proto->name);
        if (unlikely_(nb_colls > 100)) {
            SLOG(LOG_NOTICE, "Dump of first key for h = %u :", h);
            SLOG_HEX(LOG_NOTICE, TAILQ_FIRST(&list->list)->key, mux_proto->key_size);
        }
    }

    // get a new ref on the subparser for our caller (*before* releasing the mutex!)
    if (subparser) subparser = ref(&subparser->ref);

    mutex_unlock(mutex);

#   ifdef __GNUC__
    (void)__sync_add_and_fetch(&mux_proto->nb_lookups, 1);
    (void)__sync_add_and_fetch(&mux_proto->nb_collisions, nb_colls);
#   else
    mutex_lock(&mux_proto->proto.lock);
    mux_proto->nb_lookups ++;
    mux_proto->nb_collisions += nb_colls;
    mutex_unlock(&mux_proto->proto.lock);
#   endif

    if (subparser || ! create_proto) return subparser;

    // Create a new one
    return mux_subparser_and_parser_new(mux_parser, create_proto, requestor, key, now);
}

void mux_subparser_change_key(struct mux_subparser *subparser, struct mux_parser *mux_parser, void const *key)
{
    SLOG(LOG_DEBUG, "Changing key for subparser @%p", subparser);

    struct mux_proto *mux_proto = DOWNCAST(mux_parser->parser.proto, proto, mux_proto);
    unsigned new_h = hash_key(key, mux_proto->key_size, mux_parser->hash_size);
    struct subparsers *new_list = list_of_h_idx(mux_parser, new_h);
    struct mutex *new_mutex = mutex_of_h_idx(mux_parser, new_h);
    struct subparsers *cur_list;
    struct mutex *cur_mutex;

    // Loop until we grab the two required locks (former list and new list)
    do {
        unsigned const h_idx = subparser->h_idx;
        if (h_idx == NOT_HASHED) return;
        cur_list = list_of_subparser_(subparser, h_idx);
        if (cur_list == new_list) return;
        cur_mutex = mutex_of_subparser_(subparser, h_idx);

        mutex_lock2(cur_mutex, new_mutex);
        // by the time the locks are acquired maybe another thread changed subparser->h_idx?
        if (h_idx == (unsigned volatile)subparser->h_idx) break;
        SLOG(LOG_WARNING, "Subparser list changed while waiting for list mutex");
        mutex_unlock(cur_mutex);
        mutex_unlock(new_mutex);
    } while (1);

    // The caller is supposed to own a ref so we don't mind deindexing...
    // Remove
    mux_subparser_deindex_locked(subparser);
    // Change key
    memcpy(subparser->key, key, mux_proto->key_size);
    subparser->h_idx = new_h;
    // Reindex
    mux_subparser_index(subparser);
    mutex_unlock(cur_mutex);
    mutex_unlock(new_mutex);
}

int mux_parser_ctor(struct mux_parser *mux_parser, struct mux_proto *mux_proto)
{
    if (unlikely_(0 != parser_ctor(&mux_parser->parser, &mux_proto->proto))) return -1;

    mux_parser->hash_size = mux_proto->hash_size;   // We start with this size of hash
    mux_parser->nb_max_children = mux_proto->nb_max_children;   // we copy it since the user may want to change this value for future mux_parsers
    mux_parser->nb_children = 0;

    for (unsigned h = 0; h < mux_parser->hash_size; h++) {
        struct subparsers *const list = mux_parser->subparsers + h;
        TAILQ_INIT(&list->list);
    }

    return 0;
}

size_t mux_parser_size(struct mux_proto *mux_proto)
{
    struct mux_parser unused_ mux_parser;   // for the following sizeofs
    return sizeof(mux_parser) + mux_proto->hash_size * sizeof(*mux_parser.subparsers);
}

struct parser *mux_parser_new(struct proto *proto)
{
    MALLOCER(mux_parsers);
    struct mux_proto *mux_proto = DOWNCAST(proto, proto, mux_proto);
    struct mux_parser *mux_parser = MALLOC(mux_parsers, mux_parser_size(mux_proto));
    if (unlikely_(! mux_parser)) return NULL;

    if (unlikely_(0 != mux_parser_ctor(mux_parser, mux_proto))) {
        FREE(mux_parser);
        return NULL;
    }

    return &mux_parser->parser;
}

void mux_parser_dtor(struct mux_parser *mux_parser)
{
    SLOG(LOG_DEBUG, "Destructing mux_parser@%p", mux_parser);

    // We are going to delete our users. Since we are destructing, we should have ref_count=0.
    // So, as we are unreachable none of our subparser can backfire at us.
    assert(mux_parser->parser.ref.count == 0);

    /* Unref all children.
     * Beware than deleting a subparser can lead to the creation of a new parser.
     * Also, even if subparsers cannot reach us they can reach the hash list they are on!
     * Hopefully since we are not reachable no new subparser will end up in our hash (addition
     * or change key require a ref on us). */
    for (unsigned h = 0; h < mux_parser->hash_size; h++) {
        struct subparsers *const list = list_of_h_idx(mux_parser, h);
        struct mutex *const mutex = mutex_of_h_idx(mux_parser, h);

        mutex_lock(mutex);
        struct mux_subparser *subparser;
        while (NULL != (subparser = TAILQ_FIRST(&list->list))) {
            assert(subparser->h_idx % mux_parser->hash_size == h);
            mux_subparser_deindex_locked(subparser);
        }
        mutex_unlock(mutex);
    }
    assert(mux_parser->nb_children == 0);

    // Then ancestor parser
    parser_dtor(&mux_parser->parser);
}

void mux_parser_del(struct parser *parser)
{
    struct mux_parser *mux_parser = DOWNCAST(parser, parser, mux_parser);
    mux_parser_dtor(mux_parser);
    FREE(mux_parser);
}

void mux_proto_ctor(struct mux_proto *mux_proto, struct proto_ops const *ops, struct mux_proto_ops const *mux_ops, char const *name, size_t key_size, unsigned hash_size)
{
    proto_ctor(&mux_proto->proto, ops, name);
    mux_proto->ops = *mux_ops;
    mux_proto->hash_size = hash_size;
    mux_proto->key_size = key_size;
    mux_proto->nb_max_children = 0;
    mux_proto->nb_infanticide = 0;
    mux_proto->nb_collisions = 0;
    mux_proto->nb_lookups = 0;
    mux_proto->nb_timeouts = 0;
    for (unsigned m = 0; m < NB_ELEMS(mux_proto->mutexes); m++) {
        mutex_ctor_with_type(mux_proto->mutexes+m, "subparsers", PTHREAD_MUTEX_RECURSIVE);
    }
    LIST_INSERT_HEAD(&mux_protos, mux_proto, entry);
}

void mux_proto_dtor(struct mux_proto *mux_proto)
{
    LIST_REMOVE(mux_proto, entry);
    for (unsigned m = 0; m < NB_ELEMS(mux_proto->mutexes); m++) {
        mutex_dtor(mux_proto->mutexes+m);
    }
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
    proto_ctor(&uniq_proto->proto, ops, name);
    uniq_proto->parser = NULL;
}

void uniq_proto_dtor(struct uniq_proto *uniq_proto)
{
    uniq_proto->parser = parser_unref(uniq_proto->parser);
    proto_dtor(&uniq_proto->proto);
}

struct parser *uniq_parser_new(struct proto *proto)
{
    struct uniq_proto *uniq_proto = DOWNCAST(proto, proto, uniq_proto);
    mutex_lock(&proto->lock);
    if (! uniq_proto->parser) {
        uniq_proto->parser = parser_new(proto);
    }
    mutex_unlock(&proto->lock);

    SLOG(LOG_DEBUG, "New user for uniq parser %s", parser_name(uniq_proto->parser));

    return parser_ref(uniq_proto->parser);
}

void uniq_parser_del(struct parser *parser)
{
    struct uniq_proto unused_ *uniq_proto = DOWNCAST(parser->proto, proto, uniq_proto);
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
        scm_cons(scm_from_locale_symbol("nb-infanticide"),  scm_from_uint64(mux_proto->nb_infanticide)),
        scm_cons(scm_from_locale_symbol("nb-collisions"),   scm_from_uint64(mux_proto->nb_collisions)),
        scm_cons(scm_from_locale_symbol("nb-lookups"),      scm_from_uint64(mux_proto->nb_lookups)),
        scm_cons(scm_from_locale_symbol("nb-timeouts"),     scm_from_uint64(mux_proto->nb_timeouts)),
        SCM_UNDEFINED);
    return alist;
}

static struct ext_function sg_proto_stats;
static SCM g_proto_stats(SCM name_)
{
    struct proto *proto = proto_of_scm_name(name_);
    if (! proto) return SCM_UNSPECIFIED;

    return scm_list_n(
        // We use scm_from_locale_symbol a lot: hopefully the symbol will always be the same.
        // Maybe we could/should build the symbol once at init time, but I'm not sure symbols are not garbage collected.
        // So we should also declare a permanent ref on them ?
        scm_cons(scm_from_locale_symbol("nb-frames"),  scm_from_int64(proto->nb_frames)),
        scm_cons(scm_from_locale_symbol("nb-bytes"),   scm_from_int64(proto->nb_bytes)),
        scm_cons(scm_from_locale_symbol("nb-parsers"), scm_from_uint(proto->nb_parsers)),
        scm_cons(scm_from_locale_symbol("nb-fuzzed"),  scm_from_uint(proto->fuzzed_times)),
        SCM_UNDEFINED);
}

static struct ext_function sg_mux_proto_set_max_children;
static SCM g_mux_proto_set_max_children(SCM name_, SCM nb_max_children_)
{
    struct mux_proto *mux_proto = mux_proto_of_scm_name(name_);
    if (! mux_proto) return SCM_UNSPECIFIED;

    unsigned const nb_max_children = scm_to_uint(nb_max_children_); // beware: don't take the lock before scm_to_uint() which can raise an exception
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
    ext_param_nb_fuzzed_bits_init();
    ext_param_mux_timeout_init();

    ext_function_ctor(&sg_proto_stats,
        "proto-stats", 1, 0, 0, g_proto_stats,
        "(proto-stats \"proto-name\"): returns some statistics about this protocolar parser, such as number of instances.\n"
        "See also (? 'proto-names) for a list of protocol names.\n");

    ext_function_ctor(&sg_proto_names,
        "proto-names", 0, 0, 0, g_proto_names,
        "(proto-names): returns the list of availbale protocol names.\n");

    ext_function_ctor(&sg_mux_proto_names,
        "mux-names", 0, 0, 0, g_mux_proto_names,
        "(mux-names): returns the list of availbale protocol names that are multiplexers.\n");

    ext_function_ctor(&sg_mux_proto_stats,
        "mux-stats", 1, 0, 0, g_mux_proto_stats,
        "(mux-stats \"proto-name\"): returns various stats about this multiplexer.\n"
        "See also (? 'mux-names) for a list of protocol names that are multiplexers.\n"
        "         (? 'set-max-children) and (? 'set-mux-hash-size) for altering a multiplexer.\n");

    ext_function_ctor(&sg_mux_proto_set_max_children,
        "set-max-children", 2, 0, 0, g_mux_proto_set_max_children,
        "(set-max-children \"proto-name\" n): limits the number of children of each parser of this protocol to n.\n"
        "Once n is reached, a child is killed at random.\n"
        "If n is 0, then there is no such limit.\n"
        "See also (? 'mux-names) for a list of protocol names that are multiplexers.\n");

    ext_function_ctor(&sg_mux_proto_set_hash_size,
        "set-mux-hash-size", 2, 0, 0, g_mux_proto_set_hash_size,
        "(set-mux-hash-size \"proto-name\" n): sets the hash size for newly created parsers of this protocol.\n"
        "Beware of max allowed childrens whenever you change this value.\n"
        "See also (? 'set-max-children) for setting the max number of allowed child for newly created parsers of a protocol.\n"
        "         (? 'mux-names) for a list of protocol names that are multiplexers.\n");

    dummy_init();
}

void proto_fini(void)
{
    dummy_fini();
    ext_param_mux_timeout_fini();
    ext_param_nb_fuzzed_bits_fini();
    log_category_proto_fini();
}
