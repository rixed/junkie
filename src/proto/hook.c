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
#include "junkie/tools/log.h"
#include "junkie/tools/mutex.h"
#include "junkie/proto/proto.h"

void hook_ctor(struct hook *hook, char const *name)
{
    SLOG(LOG_DEBUG, "Constructing hook %s", name);
    hook->name = name;
    LIST_INIT(&hook->subscribers);
    rwlock_ctor(&hook->lock, name);
}

void hook_dtor(struct hook *hook)
{
    SLOG(LOG_DEBUG, "Destructing hook %s", hook->name);
    if (! LIST_EMPTY(&hook->subscribers)) {
        SLOG(LOG_NOTICE, "Some subscribers of hook %s are still registered", hook->name);
    }
    rwlock_dtor(&hook->lock);
}

int hook_subscriber_ctor(struct hook *hook, struct proto_subscriber *sub, proto_cb_t *cb)
{
    SLOG(LOG_DEBUG, "Construct a new subscriber for %s @%p", hook->name, sub);
    sub->cb = cb;
    WITH_WRITE_LOCK(&hook->lock) {
        LIST_INSERT_HEAD(&hook->subscribers, sub, entry);
    }
    return 0;
}

void hook_subscriber_dtor(struct hook *hook, struct proto_subscriber *sub)
{
    SLOG(LOG_DEBUG, "Destruct subscriber of %s @%p", hook->name, sub);
    WITH_WRITE_LOCK(&hook->lock) {
        LIST_REMOVE(sub, entry);
    }
}

void hook_subscribers_call(struct hook *hook, struct proto_info *info, size_t tot_cap_len, uint8_t const *tot_packet, struct timeval const *now)
{
    WITH_READ_LOCK(&hook->lock) {
        struct proto_subscriber *sub;
        LIST_FOREACH(sub, &hook->subscribers, entry) {
            sub->cb(sub, info, tot_cap_len, tot_packet, now);
        }
    }
}

