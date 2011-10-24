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
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include "junkie/tools/ext.h"
#include "junkie/tools/miscmacs.h"
#include "junkie/tools/objalloc.h"
#include "junkie/tools/log.h"

#undef LOG_CAT
#define LOG_CAT objalloc_log_category
LOG_CATEGORY_DEF(objalloc);

#define LOG_OBJ_SIZE_MAX 20U
#define PRESET_ENTRY_SIZE 2000

static size_t obj_size_max = 0;   // max size used

static struct fixed_objalloc {
    struct redim_array ra;
    char name[40];
} fixed_objallocs[LOG_OBJ_SIZE_MAX];

#define SPECIALIZE_COUNT 10000
static struct specialized_objalloc {
    struct redim_array *ra;
    char *name;
    unsigned count;
} spec_objallocs[10000];

// Returns the minimum n such that 2^n >= s
static unsigned ceil_log_2(size_t s)
{
    size_t r = 0;
    while ((1U<<r) < s) r++;
    return r;
}

struct redim_array *objalloc_for_size(size_t entry_size)
{
    // first check for a specialized version
    if (entry_size < NB_ELEMS(spec_objallocs)) {
        if (spec_objallocs[entry_size].ra) return spec_objallocs[entry_size].ra;
        if (spec_objallocs[entry_size].count++ > SPECIALIZE_COUNT) {
            spec_objallocs[entry_size].ra = malloc(sizeof(*spec_objallocs[entry_size].ra));
            if (spec_objallocs[entry_size].ra) {
                spec_objallocs[entry_size].name = strdup(tempstr_printf("spec_alloc[%zu]", entry_size));
                redim_array_ctor(spec_objallocs[entry_size].ra, PRESET_ENTRY_SIZE, entry_size, spec_objallocs[entry_size].name);
                return spec_objallocs[entry_size].ra;
            }
        }
    }

    unsigned s = ceil_log_2(entry_size);

    entry_size = ((size_t)1)<<s;
    if (entry_size > obj_size_max) {
        obj_size_max = entry_size;
        SLOG(LOG_INFO, "Max obj size is now %zu", entry_size);
    }

    assert(s < NB_ELEMS(fixed_objallocs));

    return &fixed_objallocs[s].ra;
}

extern inline void *objalloc(size_t);
extern inline void objfree(void *);

char *objalloc_strdup(char const *str)
{
    size_t len = strlen(str) + 1;
    char *str2 = objalloc(len);
    if (! str2) return NULL;
    memcpy(str2, str, len);
    return str2;
}

static unsigned inited;
void objalloc_init(void)
{
    if (inited++) return;
    redim_array_init();

    log_category_objalloc_init();

    for (unsigned f = 0; f < NB_ELEMS(fixed_objallocs); f++) {
        size_t const entry_size = 1U<<f;
        snprintf(fixed_objallocs[f].name, sizeof(fixed_objallocs[f].name), "fixed_alloc[%zu]", entry_size);
        int err = redim_array_ctor(&fixed_objallocs[f].ra, PRESET_ENTRY_SIZE, entry_size, fixed_objallocs[f].name);
        assert(!err);
    }

    for (unsigned f = 0; f < NB_ELEMS(spec_objallocs); f++) {
        spec_objallocs[f].ra = NULL;
        spec_objallocs[f].name = NULL;
        spec_objallocs[f].count = 0;
    }
}

void objalloc_fini(void)
{
    if (--inited) return;

    // Destruct all precalc objalloc
    for (unsigned f = 0; f < NB_ELEMS(fixed_objallocs); f++) {
        redim_array_dtor(&fixed_objallocs[f].ra);
    }

    // Destruct all specialized objalloc, freeing their names.
    for (unsigned f = 0; f < NB_ELEMS(spec_objallocs); f++) {
        if (spec_objallocs[f].ra) {
            redim_array_dtor(spec_objallocs[f].ra);
            free(spec_objallocs[f].ra);
            spec_objallocs[f].ra = NULL;
        }
        if (spec_objallocs[f].name) {
            free(spec_objallocs[f].name);
            spec_objallocs[f].name = NULL;
        }
    }

    log_category_objalloc_fini();

    redim_array_fini();
}

