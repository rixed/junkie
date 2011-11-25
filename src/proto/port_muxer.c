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
#include <stdint.h>
#include <inttypes.h>
#include "junkie/tools/log.h"
#include "junkie/tools/mallocer.h"
#include "junkie/proto/port_muxer.h"

#undef LOG_CAT
#define LOG_CAT proto_log_category

void port_muxer_list_ctor(struct port_muxer_list *muxers, char const *name)
{
    mutex_ctor(&muxers->mutex, name);
    TAILQ_INIT(&muxers->muxers);
}

void port_muxer_list_dtor(struct port_muxer_list *muxers)
{
    assert(TAILQ_EMPTY(&muxers->muxers));
    mutex_dtor(&muxers->mutex);
}

static unsigned range_size(struct port_muxer const *muxer)
{
    return muxer->port_max - muxer->port_min;
}

void port_muxer_ctor(struct port_muxer *muxer, struct port_muxer_list *muxers, uint16_t port_min, uint16_t port_max, struct proto *proto)
{
    SLOG(LOG_DEBUG, "Adding proto %s for ports between %"PRIu16" and %"PRIu16, proto->name, port_min, port_max);
    muxer->port_min = MIN(port_min, port_max);
    muxer->port_max = MAX(port_min, port_max);
    muxer->proto = proto;
    muxer->malloced = false;
    mutex_lock(&muxers->mutex);
    // Insert this new muxer in the list in an orderly manner, the more "precise" matchings first
    struct port_muxer *other;
    TAILQ_FOREACH(other, &muxers->muxers, entry) {
        if (range_size(muxer) <= range_size(other)) {    // insert before
            SLOG(LOG_DEBUG, "   before range %"PRIu16"-%"PRIu16, other->port_min, other->port_max);
            TAILQ_INSERT_BEFORE(other, muxer, entry);
            goto inserted;
        }
    }
    SLOG(LOG_DEBUG, "  at the end of port muxers list");
    TAILQ_INSERT_TAIL(&muxers->muxers, muxer, entry);
inserted:
    mutex_unlock(&muxers->mutex);
}

void port_muxer_dtor(struct port_muxer *muxer, struct port_muxer_list *muxers)
{
    SLOG(LOG_DEBUG, "Removing proto %s for ports between %"PRIu16" and %"PRIu16, muxer->proto->name, muxer->port_min, muxer->port_max);
    mutex_lock(&muxers->mutex);
    TAILQ_REMOVE(&muxers->muxers, muxer, entry);
    mutex_unlock(&muxers->mutex);
}

struct port_muxer *port_muxer_new(struct port_muxer_list *muxers, uint16_t port_min, uint16_t port_max, struct proto *proto)
{
    MALLOCER(port_muxer);
    struct port_muxer *muxer = MALLOC(port_muxer, sizeof(*muxer));
    if (! muxer) return NULL;
    port_muxer_ctor(muxer, muxers, port_min, port_max, proto);
    muxer->malloced = true;
    return muxer;
}

void port_muxer_del(struct port_muxer *muxer, struct port_muxer_list *muxers)
{
    port_muxer_dtor(muxer, muxers);
    if (muxer->malloced) {
        muxer->malloced = false;
        FREE(muxer);
    }
}

struct proto *port_muxer_find(struct port_muxer_list *muxers, uint16_t port)
{
    struct port_muxer *muxer;
    mutex_lock(&muxers->mutex);
    TAILQ_FOREACH(muxer, &muxers->muxers, entry) {
        if (port >= muxer->port_min && port <= muxer->port_max) {
            break;
        }
    }
    mutex_unlock(&muxers->mutex);
    return muxer ? muxer->proto : NULL;    // FIXME: should return merely a port_muxer
}

/*
 * Extension functions
 */

static SCM proto_sym;
static SCM port_min_sym;
static SCM port_max_sym;

SCM g_port_muxer_list(struct port_muxer_list *muxers)
{
    SCM ret = SCM_EOL;
    struct port_muxer *muxer;
    mutex_lock(&muxers->mutex);
    TAILQ_FOREACH(muxer, &muxers->muxers, entry) {
        SCM muxer_def = scm_list_3(
            scm_cons(proto_sym,    scm_from_locale_string(muxer->proto->name)),
            scm_cons(port_min_sym, scm_from_uint16(muxer->port_min)),
            scm_cons(port_max_sym, scm_from_uint16(muxer->port_max)));
        ret = scm_cons(muxer_def, ret);
    }
    mutex_unlock(&muxers->mutex);
    return ret;
}

SCM g_port_muxer_add(struct port_muxer_list *muxers, SCM name_, SCM port_min_, SCM port_max_)
{
    struct proto *proto = proto_of_scm_name(name_);
    uint16_t port_min = scm_to_uint16(port_min_);
    uint16_t port_max = SCM_UNBNDP(port_max_) ? port_min : scm_to_uint16(port_max_);

    struct port_muxer *muxer = port_muxer_new(muxers, port_min, port_max, proto);
    return muxer ? SCM_BOOL_T : SCM_BOOL_F;
}

SCM g_port_muxer_del(struct port_muxer_list *muxers, SCM name_, SCM port_min_, SCM port_max_)
{
    struct proto *proto = proto_of_scm_name(name_);
    uint16_t port_min = scm_to_uint16(port_min_);
    uint16_t port_max = SCM_UNBNDP(port_max_) ? port_min : scm_to_uint16(port_max_);

    struct port_muxer *muxer;
    mutex_lock(&muxers->mutex);
    TAILQ_FOREACH(muxer, &muxers->muxers, entry) {
        if (proto == muxer->proto && port_min == muxer->port_min && port_max == muxer->port_max) {
            break;
        }
    }
    mutex_unlock(&muxers->mutex);

    if (! muxer) return SCM_BOOL_F;

    port_muxer_del(muxer, muxers);
    return SCM_BOOL_T;
}

void port_muxer_init(void)
{
    proto_sym    = scm_permanent_object(scm_from_latin1_symbol("proto"));
    port_min_sym = scm_permanent_object(scm_from_latin1_symbol("port-min"));
    port_max_sym = scm_permanent_object(scm_from_latin1_symbol("port-max"));
}

void port_muxer_fini(void)
{
}
