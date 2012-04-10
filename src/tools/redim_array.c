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
#include <string.h>
#include <assert.h>
#include "junkie/tools/ext.h"
#include "junkie/tools/log.h"
#include "junkie/tools/redim_array.h"
#include "junkie/tools/mallocer.h"
#include "junkie/tools/mutex.h"

#undef LOG_CAT
#define LOG_CAT redim_array_log_category
LOG_CATEGORY_DEF(redim_array);

static LIST_HEAD(redim_arrays, redim_array) redim_arrays = LIST_HEAD_INITIALIZER(redim_arrays);
static struct mutex redim_arrays_mutex;

/*
 * Array chunks
 */

struct freecell {   // when an object is freed that is not at the last entry, add it to the free list.
    SLIST_ENTRY(freecell) entry;
};

/* A malloced cell can be either used or unused (ie. before nb_used or after).
 * A used cell can be freed or not (ie on the free list or not).
 * We make no effort to reduce nb_used when cells are freed.
 * Instead, chunks are cleared globally when nb_holes reach nb_malloced. */
struct redim_array_chunk {
    TAILQ_ENTRY(redim_array_chunk) entry;
    SLIST_HEAD(freecells, freecell) freelist;    // the list of free cells in this redim_array (ie. cells before nb_used that were freed).
    unsigned nb_used;    // either alloced to user or on the freelist
    unsigned nb_malloced;
    unsigned nb_holes;  // size of freelist
    struct redim_array *array;
    char bytes[];   // Beware: variable size !
};

// Caller must own chunks_mutex
static struct redim_array_chunk *chunk_new(struct redim_array *ra)
{
    MALLOCER(redim_array);
    struct redim_array_chunk *chunk = MALLOC(redim_array, sizeof(*chunk) + ra->alloc_size * ra->entry_size);
    SLOG(LOG_INFO, "New chunk@%p of %zu bytes for array %s@%p", chunk, (ra->alloc_size * ra->entry_size), ra->name, ra);

    TAILQ_INSERT_TAIL(&ra->chunks, chunk, entry);
    chunk->nb_used = 0;
    chunk->nb_malloced = ra->alloc_size;
    SLIST_INIT(&chunk->freelist);
    chunk->nb_holes = 0;
    chunk->array = ra;
    ra->nb_malloced += chunk->nb_malloced;
    return chunk;
}

// Caller must own chunks_mutex
static void chunk_del(struct redim_array_chunk *chunk)
{
    SLOG(LOG_INFO, "Del chunk@%p of array %s@%p", chunk, chunk->array->name, chunk->array);
    TAILQ_REMOVE(&chunk->array->chunks, chunk, entry);
    chunk->array->nb_used -= chunk->nb_used;
    chunk->array->nb_malloced -= chunk->nb_malloced;
    chunk->array->nb_holes -= chunk->nb_holes;
    FREE(chunk);
}

/*
 * Redim Array
 */

int redim_array_ctor(struct redim_array *ra, unsigned alloc_size, size_t entry_size, char const *name)
{
    entry_size = MAX(entry_size, sizeof(struct freecell));
    SLOG(LOG_INFO, "Construct redim_array %s@%p for entries of size %zu", name, ra, entry_size);
    ra->nb_used = 0;
    ra->nb_malloced = 0;
    ra->nb_holes = 0;
    ra->alloc_size = alloc_size;
    ra->entry_size = entry_size;
    ra->name = name;
    TAILQ_INIT(&ra->chunks);
    mutex_ctor(&ra->chunks_mutex, "redim_array chunks");
    mutex_lock(&redim_arrays_mutex);
    LIST_INSERT_HEAD(&redim_arrays, ra, entry);
    mutex_unlock(&redim_arrays_mutex);
    return 0;
}

void redim_array_dtor(struct redim_array *ra)
{
    SLOG(LOG_INFO, "Destruct redim_array %s@%p", ra->name, ra);
    redim_array_clear(ra);
    mutex_lock(&redim_arrays_mutex);
    LIST_REMOVE(ra, entry);
    mutex_unlock(&redim_arrays_mutex);
    mutex_dtor(&ra->chunks_mutex);
}

/*
 * Access to array cells
 */

/// returns the nth malloced entry in a chunk
static void *chunk_entry(struct redim_array_chunk *chunk, unsigned n)
{
    return chunk->bytes + n * chunk->array->entry_size;
}

void *redim_array_get(struct redim_array *ra)
{
    void *ret = NULL;

    mutex_lock(&ra->chunks_mutex);

    // Look for the first chunk with free or unused cells
    struct redim_array_chunk *chunk;
    TAILQ_FOREACH(chunk, &ra->chunks, entry) {  // a specific list for unfilled chunks seams overkill
        if (! SLIST_EMPTY(&chunk->freelist)) {
            ret = SLIST_FIRST(&chunk->freelist);
            SLIST_REMOVE_HEAD(&chunk->freelist, entry);
            chunk->nb_holes --;
            ra->nb_holes --;
            goto quit;
        }
        if (chunk->nb_used < chunk->nb_malloced) {
            ret = chunk_entry(chunk, chunk->nb_used++);
            ra->nb_used ++;
            goto quit;
        }
    }

    assert(! chunk);
    chunk = chunk_new(ra);
    assert(chunk);  // FIXME: handle NULL result from redim_array_get
    ret = chunk_entry(chunk, chunk->nb_used++);
    ra->nb_used ++;
quit:
    SLOG(LOG_DEBUG, "Get cell@%p from array@%p", ret, ra);
    mutex_unlock(&ra->chunks_mutex);
    return ret;
}

void redim_array_free(struct redim_array *ra, void *cell)
{
    SLOG(LOG_DEBUG, "Freeing cell@%p from array@%p", cell, ra);

    mutex_lock(&ra->chunks_mutex);

    // Find the relevant chunk
    struct redim_array_chunk *chunk;
    TAILQ_FOREACH(chunk, &ra->chunks, entry) {
        if (cell >= chunk_entry(chunk, 0) && cell < chunk_entry(chunk, chunk->nb_used)) break;
    }
    assert(chunk);
    assert(chunk->nb_malloced >= chunk->nb_used);
    assert(chunk->nb_used >= chunk->nb_holes+1);

    struct freecell *cell_ = cell;
    SLIST_INSERT_HEAD(&chunk->freelist, cell_, entry);
    chunk->nb_holes ++;
    chunk->array->nb_holes ++;
    if (chunk->nb_holes == chunk->nb_used) {
        chunk_del(chunk);
    }

    mutex_unlock(&ra->chunks_mutex);
}

void redim_array_clear(struct redim_array *ra)
{
    mutex_lock(&ra->chunks_mutex);
    struct redim_array_chunk *chunk;
    while (NULL != (chunk = TAILQ_LAST(&ra->chunks, redim_array_chunks))) {
        chunk_del(chunk);
    }
    assert(ra->nb_used == 0);
    assert(ra->nb_malloced == 0);
    assert(ra->nb_holes == 0);
    mutex_unlock(&ra->chunks_mutex);
}

int redim_array_foreach(struct redim_array *ra, int (*cb)(struct redim_array *, void *cell, va_list), ...)
{
    int ret = 0;
    va_list ap;
    va_start(ap, cb);

    mutex_lock(&ra->chunks_mutex);  // Callback is not allowed to mess with the redim_array
    struct redim_array_chunk *chunk;
    TAILQ_FOREACH(chunk, &ra->chunks, entry) {
        assert(chunk->nb_malloced >= chunk->nb_used);
        assert(chunk->nb_used >= chunk->nb_holes);
        for (unsigned c = 0; c < chunk->nb_used; c++) {
            va_list aq;
            va_copy(aq, ap);
            ret = cb(ra, chunk_entry(chunk, c), aq);
            va_end(aq);
            if (ret) goto quit;
        }
    }
quit:
    mutex_unlock(&ra->chunks_mutex);

    va_end(ap);
    return ret;
}

/*
 * Extensions
 */

static struct ext_function sg_array_names;
static SCM g_array_names(void)
{
    SCM ret = SCM_EOL;
    struct redim_array *array;
    mutex_lock(&redim_arrays_mutex);
    LIST_FOREACH(array, &redim_arrays, entry) ret = scm_cons(scm_from_locale_string(array->name), ret);
    mutex_unlock(&redim_arrays_mutex);
    return ret;
}

static struct redim_array *array_of_scm_name(SCM name_)
{
    char *name = scm_to_tempstr(name_);
    struct redim_array *array;
    LIST_LOOKUP_LOCKED(array, &redim_arrays, entry, 0 == strcasecmp(name, array->name), &redim_arrays_mutex);
    return array;
}

static SCM nb_used_sym;
static SCM nb_malloced_sym;
static SCM nb_holes_sym;
static SCM alloc_size_sym;
static SCM entry_size_sym;

static struct ext_function sg_array_stats;
static SCM g_array_stats(SCM name_)
{
    struct redim_array *array = array_of_scm_name(name_);
    if (! array) return SCM_UNSPECIFIED;

    return scm_list_5(
        scm_cons(nb_used_sym,     scm_from_uint(array->nb_used)),
        scm_cons(nb_malloced_sym, scm_from_uint(array->nb_malloced)),
        scm_cons(nb_holes_sym,    scm_from_uint(array->nb_holes)),
        scm_cons(alloc_size_sym,  scm_from_uint(array->alloc_size)),
        scm_cons(entry_size_sym,  scm_from_size_t(array->entry_size)));
}

static unsigned inited;
void redim_array_init(void)
{
    if (inited++) return;
    ext_init();
    mutex_init();
    mallocer_init();

    log_category_redim_array_init();

    mutex_ctor(&redim_arrays_mutex, "redim_arrays");
    nb_used_sym     = scm_permanent_object(scm_from_latin1_symbol("nb-used"));
    nb_malloced_sym = scm_permanent_object(scm_from_latin1_symbol("nb-malloced"));
    nb_holes_sym    = scm_permanent_object(scm_from_latin1_symbol("nb-holes"));
    alloc_size_sym  = scm_permanent_object(scm_from_latin1_symbol("alloc-size"));
    entry_size_sym  = scm_permanent_object(scm_from_latin1_symbol("entry-size"));

    ext_function_ctor(&sg_array_names,
        "array-names", 0, 0, 0, g_array_names,
        "(array-names): returns the list of available array names.\n");

    ext_function_ctor(&sg_array_stats,
        "array-stats", 1, 0, 0, g_array_stats,
        "(array-stats \"array-name\"): returns some statistics about this array, such as current number of elements.\n"
        "Note: Beware that alloc-size is given in entries, not bytes !\n"
        "See also (? 'array-names) for a list of array names.\n");
}

void redim_array_fini(void)
{
    if (--inited) return;

    log_category_redim_array_fini();
    mallocer_fini();
    mutex_dtor(&redim_arrays_mutex);
    mutex_fini();
    ext_fini();
}
