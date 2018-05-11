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
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h> // for access
#include "junkie/tools/log.h"
#include "junkie/tools/objalloc.h"
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
    if (! TAILQ_EMPTY(&muxers->muxers)) {
        SLOG(LOG_WARNING, "A protocol is still using destructed port muxer. We're going to crash if this user unsubscribe.");
    }
    mutex_dtor(&muxers->mutex);
}

static unsigned range_size(struct port_muxer const *muxer)
{
    return muxer->port_max - muxer->port_min;
}

void port_muxer_ctor(struct port_muxer *muxer, struct port_muxer_list *muxers, uint16_t port_min, uint16_t port_max, struct proto *proto)
{
    SLOG(LOG_DEBUG, "Adding proto %s for ports between %"PRIu16" and %"PRIu16, proto->name, port_min, port_max);
    if (port_max == 0) port_max = port_min;
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
    struct port_muxer *muxer = objalloc(sizeof(*muxer), "port muxers");
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
        objfree(muxer);
    }
}

static bool port_belongs_to_muxer(struct port_muxer const *muxer, uint16_t port)
{
    return port >= muxer->port_min && port <= muxer->port_max;
}

struct proto *port_muxer_find(struct port_muxer_list *muxers, uint16_t port1, uint16_t port2)
{
    struct port_muxer *muxer;
    mutex_lock(&muxers->mutex);
    TAILQ_FOREACH(muxer, &muxers->muxers, entry) {
        if (
            port_belongs_to_muxer(muxer, port1) ||
            port_belongs_to_muxer(muxer, port2)
        ) {
            break;
        }
    }
    mutex_unlock(&muxers->mutex);
    return muxer ? muxer->proto : NULL;    // FIXME: should return merely a port_muxer
}

/*
 * Port key related function
 */

void port_key_init(struct port_key *key, uint16_t src, uint16_t dst, unsigned way)
{
    if (way == 0) {
        key->port[0] = src;
        key->port[1] = dst;
    } else {
        key->port[0] = dst;
        key->port[1] = src;
    }
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
            scm_cons(proto_sym,    scm_from_latin1_string(muxer->proto->name)),
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
    mutex_unlock(&muxers->mutex);   // FIXME: so someone else may delete it concurrently?

    if (! muxer) return SCM_BOOL_F;

    port_muxer_del(muxer, muxers);
    return SCM_BOOL_T;
}

/*
 * Simple heuristic to find out if a new TCP fragment that's not a SYN comes from
 * the client or the server.
 */

#include <junkie/tools/files.h>
static unsigned srv_ports[65536];   // count each time we encounter a server on this port
static char const *const srv_ports_file = STRIZE(VARDIR) "/srv-ports.db";

static void srv_ports_init(void)
{
    SLOG(LOG_DEBUG, "Reading server ports from '%s'", srv_ports_file);

    // Do not bark if we have no read perm to this file or if it does not exist
    if (0 != access(srv_ports_file, R_OK)) return;

    int fd = file_open(srv_ports_file, O_RDONLY);
    if (fd < 0) return;

    if (file_read(fd, srv_ports, sizeof(srv_ports)) != sizeof(srv_ports)) {
        memset(srv_ports, 0, sizeof(srv_ports));
    }

    file_close(fd);
}

static void srv_ports_fini(void)
{
    SLOG(LOG_DEBUG, "Saving server ports into '%s'", srv_ports_file);

    // Do not bark if we have no write perm to this file
    if (0 != access(srv_ports_file, W_OK)) return;

    int fd = file_open(srv_ports_file, O_WRONLY|O_CREAT|O_TRUNC);
    if (fd < 0) return;

    (void)file_write(fd, srv_ports, sizeof(srv_ports));

    file_close(fd);
}

static void incr_srv_port(uint16_t p)
{
    if (++srv_ports[p] == 0) {
        SLOG(LOG_DEBUG, "Too many cnx to port %"PRIu16", rescaling srv_ports", p);
        for (unsigned q = 0; q < NB_ELEMS(srv_ports); q++) {
            srv_ports[q] >>= 1;
        }
        srv_ports[p] = UINT_MAX>>1;
    }
}


bool comes_from_client(uint16_t const *port, bool syn, bool ack)
{
    if (syn && !ack) {
        // Note that it could still be the server part of a 4way handshake, but we ignore this possibility for now
        incr_srv_port(port[1]);
        return true;
    }
    if (syn && ack) {
        // Again, in a 4way handshake this heuristic may fail
        incr_srv_port(port[0]);
        return false;
    }
    // Trust port if one is below 1024, but do not record it in srv_ports
    if (port[0] >= 1024 && port[1] < 1024) {
        return true;
    }
    if (port[0] < 1024 && port[1] >= 1024) {
        return false;
    }
    // When in doubt, use srv_ports
    if (srv_ports[port[1]] == srv_ports[port[0]]) { // hum...
        return port[1] <= port[0];
    }
    return srv_ports[port[1]] > srv_ports[port[0]];
}

/*
 * Init
 */

void port_muxer_init(void)
{
    proto_sym    = scm_permanent_object(scm_from_latin1_symbol("proto"));
    port_min_sym = scm_permanent_object(scm_from_latin1_symbol("port-min"));
    port_max_sym = scm_permanent_object(scm_from_latin1_symbol("port-max"));
    srv_ports_init();
}

void port_muxer_fini(void)
{
    srv_ports_fini();
}
