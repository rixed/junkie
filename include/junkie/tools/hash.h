// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef HASH_H_100922
#define HASH_H_100922
#include <stdarg.h>
#include <junkie/tools/queue.h>
#include <junkie/tools/objalloc.h>
#include <junkie/tools/miscmacs.h>
#include <junkie/tools/log.h>

/** @file
 * @brief simple hash implementation in the spirit of the BSD queues.
 */

/// List of all defined hashes
extern LIST_HEAD(hashes, hash_base) hashes;

#define HASH_LENGTH_MIN 3
#define HASH_LENGTH_MAX 16
#define HASH_LENGTH_GOOD 8

#define HASH_ENTRY(type) LIST_ENTRY(type)

struct hash_base {
    LIST_ENTRY(hash_base) entry;    ///< entry in the list of all hashes
    unsigned num_lists;              ///< number of list heads in the hash table
    unsigned num_lists_min;          ///< initial number of lists (we never go below this)
    unsigned size;                  ///< number of entries in this hash
    unsigned max_size;              ///< max size since last rehash
    unsigned num_rehash;             ///< number of rehash performed
    char const *name;               ///< useful to retrieve this hash from guile
};

#define HASH_TABLE(name_, type) \
struct name_ { \
    LIST_HEAD(name_##_lists, type) *lists; \
    struct hash_base base; \
}

#define HASH_SIZE(hash) (hash)->base.size

#define HASH_INIT(hash, size_, name_) do { \
    (hash)->base.num_lists = 1 + size_ / HASH_LENGTH_GOOD; \
    (hash)->base.num_lists_min = (hash)->base.num_lists; \
    (hash)->lists = objalloc((hash)->base.num_lists * sizeof(*(hash)->lists), name_); \
    (hash)->base.size = 0; \
    (hash)->base.max_size = 0; \
    (hash)->base.num_rehash = 0; \
    (hash)->base.name = (name_); \
    LIST_INSERT_HEAD(&hashes, &(hash)->base, entry); \
    for (unsigned l = 0; l < (hash)->base.num_lists; l++) LIST_INIT((hash)->lists+l); \
} while (0)

#define HASH_DEINIT(hash) do { \
    LIST_REMOVE(&(hash)->base, entry); \
    objfree((hash)->lists); \
} while (0)

#define HASH_EMPTY(hash) ((hash)->base.size == 0)

// FIXME: HASH_FOREACH and HASH_FOREACH_SAFE are not correct since a break do not break the whole loop. Find a way to write this differently so one can break out completely.
#define HASH_FOREACH(var, hash, field) \
    for (unsigned __hash_l = 0; __hash_l < (hash)->base.num_lists; __hash_l++) \
        LIST_FOREACH(var, (hash)->lists+__hash_l, field)

#define HASH_FOREACH_SAFE(var, hash, field, tvar) \
    for (unsigned __hash_l = 0; __hash_l < (hash)->base.num_lists; __hash_l++) \
        LIST_FOREACH_SAFE(var, (hash)->lists+__hash_l, field, tvar)

#define HASH_FUNC(key) hashfun(key, sizeof(*(key)))
#define HASH_LIST(hash, key) ((hash)->lists + (HASH_FUNC(key) % (hash)->base.num_lists))

#define HASH_FOREACH_SAME_KEY(var, hash, key, key_field, field) \
    ASSERT_COMPILE(sizeof(*(key)) == sizeof((var)->key_field)); \
    LIST_FOREACH(var, HASH_LIST(hash, key), field)

#define HASH_FOREACH_SAME_KEY_SAFE(var, hash, key, key_field, field, tvar) \
    ASSERT_COMPILE(sizeof(*(key)) == sizeof((var)->key_field)); \
    LIST_FOREACH_SAFE(var, HASH_LIST(hash, key), field, tvar)

#define HASH_FOREACH_MATCH(var, hash, key, key_field, field) \
    HASH_FOREACH_SAME_KEY(var, hash, key, key_field, field) \
        if (0 == memcmp(key, &((var)->key_field), sizeof(*(key))))

#define HASH_LOOKUP(var, hash, key, key_field, field) \
    HASH_FOREACH_MATCH(var, hash, key, key_field, field) break;

#define HASH_INSERT(hash, elm, key, field) do { \
    LIST_INSERT_HEAD(HASH_LIST(hash, key), elm, field); \
    (hash)->base.size ++; \
    if ((hash)->base.size > (hash)->base.max_size) (hash)->base.max_size = (hash)->base.size; \
} while (0)

#define HASH_REMOVE(hash, elm, field) do { \
    LIST_REMOVE(elm, field); \
    (hash)->base.size --; \
} while (0)

#define HASH_AVG_LENGTH(hash) (((hash)->base.max_size + (hash)->base.num_lists/2) / (hash)->base.num_lists)

#define HASH_TRY_REHASH(hash, key_field, field) do { \
    unsigned const avg_length = HASH_AVG_LENGTH(hash); \
    if ((avg_length < HASH_LENGTH_MIN && (hash)->base.num_lists > (hash)->base.num_lists_min) || avg_length > HASH_LENGTH_MAX) { \
        unsigned new_num_lists = 1 + (hash)->base.max_size / HASH_LENGTH_GOOD; \
        __typeof__((hash)->lists) new_lists = objalloc(new_num_lists * sizeof(*(hash)->lists), (hash)->base.name); \
        if (! new_lists) break; \
        SLOG(LOG_INFO, "Rehashing hash %s from %u to %u lists (%u max entries)", (hash)->base.name, (hash)->base.num_lists, new_num_lists, (hash)->base.max_size); \
        for (unsigned l = 0; l < new_num_lists; l++) LIST_INIT(new_lists + l); \
        __typeof__((hash)->lists[0].lh_first) elm, tmp; \
        HASH_FOREACH_SAFE(elm, hash, field, tmp) { \
            LIST_REMOVE(elm, field); \
            LIST_INSERT_HEAD(new_lists + (HASH_FUNC(&elm->key_field) % new_num_lists), elm, field); \
        } \
        objfree((hash)->lists); \
        (hash)->lists = new_lists; \
        (hash)->base.num_lists = new_num_lists; \
        (hash)->base.num_rehash ++; \
    } \
    (hash)->base.max_size = (hash)->base.size; \
} while (0)

/*
 * And in case you need one, a simple and fast (for small keys) hash function:
 */

static inline uint_least32_t hashfun(void const *k_, size_t len)
{
    uint8_t const *k = k_;
    uint_least32_t h = 5381;
    while (len --) {
        h = (h << 5) + h + *k++; /* h*33 + *k++; */
    }
    return h;
}

// For compatibility with previous versions:
#define hashlittle(k, l, s) hashfun(k, l)

void hash_init(void);
void hash_fini(void);

#endif
