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

struct redim_arrays redim_arrays = LIST_HEAD_INITIALIZER(redim_arrays);

/*
 * Array chunks
 */

struct redim_array_chunk {
    TAILQ_ENTRY(redim_array_chunk) entry;
    unsigned nb_entries;
    struct redim_array *array;
    char bytes[];   // Beware: variable size !
};

static struct redim_array_chunk *chunk_new(struct redim_array *ra)
{
    MALLOCER(redim_array);
    SLOG(LOG_DEBUG, "New chunk of %zu bytes for array@%p", (ra->alloc_size * ra->entry_size), ra);
    struct redim_array_chunk *chunk = MALLOC(redim_array, sizeof(*chunk) + ra->alloc_size * ra->entry_size);

    TAILQ_INSERT_TAIL(&ra->chunks, chunk, entry);
    chunk->nb_entries = 0;
    chunk->array = ra;
    return chunk;
}

static void chunk_del(struct redim_array_chunk *chunk)
{
    SLOG(LOG_DEBUG, "Del chunk of array@%p", chunk->array);
    TAILQ_REMOVE(&chunk->array->chunks, chunk, entry);
    chunk->array->nb_entries -= chunk->nb_entries;
    FREE(chunk);
}

/*
 * Redim Array
 */

int redim_array_ctor(struct redim_array *ra, unsigned alloc_size, size_t entry_size, char const *name)
{
    ra->nb_entries = 0;
    ra->alloc_size = alloc_size;
    ra->entry_size = entry_size;
    ra->name = name;
    TAILQ_INIT(&ra->chunks);
    LIST_INSERT_HEAD(&redim_arrays, ra, entry);
    return 0;
}

void redim_array_dtor(struct redim_array *ra)
{
    redim_array_clear(ra);
    LIST_REMOVE(ra, entry);
}

/*
 * Access to array cells
 */

static void *chunk_entry(struct redim_array_chunk *chunk, unsigned n)
{
    return chunk->bytes + n * chunk->array->entry_size;
}

void redim_array_push(struct redim_array *ra, void *cell)
{
    struct redim_array_chunk *chunk = TAILQ_LAST(&ra->chunks, redim_array_chunks);

    if (! chunk || chunk->nb_entries >= ra->alloc_size) {
        chunk = chunk_new(ra);
    }

    assert(chunk);

    memcpy(chunk->bytes + chunk->nb_entries * ra->entry_size, cell, ra->entry_size);
    chunk->nb_entries ++;
    chunk->array->nb_entries ++;
}

void *redim_array_last(struct redim_array *ra)
{
    struct redim_array_chunk *chunk = TAILQ_LAST(&ra->chunks, redim_array_chunks);
    if (! chunk) return NULL;

    assert(chunk->nb_entries != 0);
    return chunk_entry(chunk, chunk->nb_entries-1);
}

void redim_array_chop(struct redim_array *ra)
{
    struct redim_array_chunk *chunk = TAILQ_LAST(&ra->chunks, redim_array_chunks);
    assert(chunk);  // This is an error to chop an empty array

    assert(chunk->nb_entries != 0);
    if (chunk->nb_entries == 1) {
        chunk_del(chunk);
    } else {
        chunk->nb_entries --;
        chunk->array->nb_entries --;
    }
}

void redim_array_clear(struct redim_array *ra)
{
    struct redim_array_chunk *chunk;
    while (NULL != (chunk = TAILQ_LAST(&ra->chunks, redim_array_chunks))) {
        chunk_del(chunk);
    }
    assert(ra->nb_entries == 0);
}


int redim_array_foreach(struct redim_array *ra, int (*cb)(struct redim_array *, void *cell, va_list), ...)
{
    int ret = 0;
    va_list ap;
    va_start(ap, cb);

    struct redim_array_chunk *chunk, *tmp;
    TAILQ_FOREACH_SAFE(chunk, &ra->chunks, entry, tmp) {
        for (unsigned c = 0; c < chunk->nb_entries; c++) {
            va_list aq;
            va_copy(aq, ap);
            ret = cb(ra, chunk_entry(chunk, c), aq);
            va_end(aq);
            if (ret) goto quit;
        }
    }
quit:
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
    LIST_FOREACH(array, &redim_arrays, entry) ret = scm_cons(scm_from_locale_string(array->name), ret);
    return ret;
}

static struct redim_array *array_of_scm_name(SCM name_)
{
    char *name = scm_to_tempstr(name_);
    struct redim_array *array;
    LIST_LOOKUP(array, &redim_arrays, entry, 0 == strcasecmp(name, array->name));
    return array;
}

static SCM nb_entries_sym;
static SCM alloc_size_sym;
static SCM entry_size_sym;

static struct ext_function sg_array_stats;
static SCM g_array_stats(SCM name_)
{
    struct redim_array *array = array_of_scm_name(name_);
    if (! array) return SCM_UNSPECIFIED;

    return scm_list_3(
        // See g_proto_stats
        scm_cons(nb_entries_sym, scm_from_uint(array->nb_entries)),
        scm_cons(alloc_size_sym, scm_from_uint(array->alloc_size)),
        scm_cons(entry_size_sym, scm_from_size_t(array->entry_size)));
}

static unsigned inited;
void redim_array_init(void)
{
    if (inited++) return;
    ext_init();

    nb_entries_sym = scm_permanent_object(scm_from_latin1_symbol("nb-entries"));
    alloc_size_sym = scm_permanent_object(scm_from_latin1_symbol("alloc-size"));
    entry_size_sym = scm_permanent_object(scm_from_latin1_symbol("entry-size"));

    ext_function_ctor(&sg_array_names,
        "array-names", 0, 0, 0, g_array_names,
        "(array-names): returns the list of availbale array names.\n");

    ext_function_ctor(&sg_array_stats,
        "array-stats", 1, 0, 0, g_array_stats,
        "(array-stats \"array-name\"): returns some statistics about this array, such as current number of elements.\n"
        "Note: Beware that alloc-size is given in entries, not bytes !\n"
        "See also (? 'array-names) for a list of array names.\n");
}

void redim_array_fini(void)
{
    if (--inited) return;

    ext_fini();
}
