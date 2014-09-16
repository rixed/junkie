// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2014, SecurActive.
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

#include "junkie/tools/timeouter.h"

void timeouter_pool_ctor(struct timeouter_pool *timeouter_pool,
        unsigned const *timeout,
        void *userdata,
        del_by_timeout *del)
{
    timeouter_pool->timeout = timeout;
    timeouter_pool->del = del;
    timeouter_pool->userdata = userdata;
    TAILQ_INIT(&timeouter_pool->list);
}

void timeouter_pool_dtor(struct timeouter_pool *timeouter_pool)
{
    struct timeouter *t;
    while (NULL != (t = TAILQ_FIRST(&timeouter_pool->list))) {
        timeouter_pool->del(timeouter_pool, t);
    }
}

void timeouter_pool_timeout(struct timeouter_pool *timeouter_pool, struct timeval const *now)
{
    struct timeouter *t;
    unsigned const timeout_time = now->tv_sec - *timeouter_pool->timeout;
    while (NULL != (t = TAILQ_LAST(&timeouter_pool->list, timeouters))) {
        if (t->last_used < timeout_time) {
            timeouter_pool->del(timeouter_pool, t);
        } else {
            break;
        }
    }
}

void timeouter_ctor(struct timeouter_pool *timeouter_pool
        , struct timeouter *timeouter, struct timeval const *now)
{
    TAILQ_INSERT_HEAD(&timeouter_pool->list, timeouter, entry);
    timeouter->last_used = now->tv_sec;
}

void timeouter_dtor(struct timeouter_pool *timeouter_pool, struct timeouter *timeouter)
{
    TAILQ_REMOVE(&timeouter_pool->list, timeouter, entry);
}

void timeouter_touch(struct timeouter_pool *timeouter_pool
        , struct timeouter *timeouter, struct timeval const *now)
{
    TAILQ_REMOVE(&timeouter_pool->list, timeouter, entry);
    TAILQ_INSERT_HEAD(&timeouter_pool->list, timeouter, entry);
    timeouter->last_used = now->tv_sec;
}

