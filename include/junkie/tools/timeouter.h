// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef TIMEOUTER_H_140820
#define TIMEOUTER_H_140820

#include <stdlib.h>
#include <junkie/tools/queue.h>
#include <junkie/tools/timeval.h>

struct timeouter_pool;
struct timeouter;
typedef void del_by_timeout (struct timeouter_pool *timeouter_pool, struct timeouter *t);

struct timeouter_pool {
    unsigned const *timeout;                 ///< So that it's easy to take this timeout from an ext_param
    TAILQ_HEAD(timeouters, timeouter) list;  ///< Least recently used last
    del_by_timeout *del; ///< Deletor for timeouter objects held here this pool
    void *userdata;
};

void timeouter_pool_ctor(struct timeouter_pool *,
        unsigned const *timeout,
        void *userdata,
        del_by_timeout *del);
void timeouter_pool_dtor(struct timeouter_pool *);

struct timeouter {
    TAILQ_ENTRY(timeouter) entry;
    time_t last_used;                       ///< Not timeval to save space
    struct timeouter_pool *timeouter_pool;  ///< Backlink to remove from pool
};

void timeouter_ctor(struct timeouter_pool *, struct timeouter *, struct timeval const *now);
void timeouter_dtor(struct timeouter_pool *, struct timeouter *);
void timeouter_touch(struct timeouter_pool *, struct timeouter *, struct timeval const *now);
void timeouter_pool_timeout(struct timeouter_pool *timeouter_pool, struct timeval const *now);

#endif
