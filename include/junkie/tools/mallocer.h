// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef MALLOCER_H_09130857
#define MALLOCER_H_09130857
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <junkie/tools/mutex.h>
#include <junkie/tools/queue.h>

/** @file
 * @brief Wrappers around malloc/free/realloc.
 */

struct mallocer_block {
    LIST_ENTRY(mallocer_block) entry;
    struct mallocer *mallocer;
    size_t size;
    time_t date;
};

struct mallocer {
    LIST_HEAD(mallocer_blocks, mallocer_block) blocks;
    SLIST_ENTRY(mallocer) entry;
    size_t tot_size;
    unsigned nb_blocks;
    unsigned nb_allocs;
    char const *name;
    bool inited;
    struct mutex mutex;
};

#define MALLOCER_DEC(name_) struct mallocer mallocer_##name_
#define MALLOCER_DEF(name_) \
    struct mallocer mallocer_##name_ = { \
        .blocks = LIST_HEAD_INITIALIZER(&mallocer_##name_.blocks), \
        .tot_size = 0, \
        .nb_blocks = 0, \
        .nb_allocs = 0, \
        .name = #name_, \
        .inited = false, \
    }

#define MALLOCER_INIT(name_) \
    if (! mallocer_##name_.inited) { \
        mutex_ctor(&mallocer_##name_.mutex, "mallocer "#name_); \
        SLIST_INSERT_HEAD(&mallocers, &mallocer_##name_, entry); \
        mallocer_##name_.inited = true; \
    }

#define MALLOCER(name_) \
    static MALLOCER_DEF(name_); \
    MALLOCER_INIT(name_)

extern SLIST_HEAD(mallocers, mallocer) mallocers;

void *mallocer_alloc(struct mallocer *, size_t);
void *mallocer_realloc(struct mallocer *, void *, size_t);
void mallocer_free(void *);
char *mallocer_strdup(struct mallocer *, char const *);

#define MALLOC(name, size) mallocer_alloc(&mallocer_##name, size)
#define REALLOC(name, ptr, size) mallocer_realloc(&mallocer_##name, ptr, size)
#define FREE(ptr) mallocer_free(ptr)
#define STRDUP(name, str) mallocer_strdup(&mallocer_##name, str)

void mallocer_init(void);
void mallocer_fini(void);

#endif
