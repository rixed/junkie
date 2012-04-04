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
#include <stdint.h>
#include <assert.h>
#include "junkie/tools/ext.h"
#include "junkie/tools/miscmacs.h"
#include "junkie/tools/objalloc.h"
#include "junkie/tools/log.h"

#undef LOG_CAT
#define LOG_CAT objalloc_log_category
LOG_CATEGORY_DEF(objalloc);

#define LOG_OBJ_SIZE_MAX 20U

static struct fixed_objalloc {
    struct redim_array ra;
    char name[40];
} fixed_objallocs[LOG_OBJ_SIZE_MAX];

static struct specialized_objalloc {
    struct redim_array *ra;
    unsigned live; // how many live objects do we have with this size *in the fixed_objallocs* !
} spec_objallocs[10000];

// Returns the minimum n such that 2^n >= s
static unsigned ceil_log_2(size_t s)
{
    size_t r = 0;
    while ((1U<<r) < s) r++;
    return r;
}

static unsigned preset_entry_size(size_t entry_size)
{
#   define CHUNK_SIZE (16*1024*1024)
#   define MIN_PRESET_SIZE 2
#   define MAX_PRESET_SIZE 3000
    // We try to alloc objects by batch of CHUNK_SIZE bytes
    unsigned n = CHUNK_SIZE/entry_size;

    if (n < MIN_PRESET_SIZE) return MIN_PRESET_SIZE;
    else if (n > MAX_PRESET_SIZE) return MAX_PRESET_SIZE;
    return n;
}

static unsigned specialize_count(unsigned preset_size)
{
    return (3*preset_size)/4;   // we won't specialize an allocator if we have less than this number of live objects
}

static bool should_specialize_for_size(size_t entry_size)
{
    unsigned const s = ceil_log_2(entry_size);
    size_t const up_size = 1U << s;

    return entry_size < (4*up_size)/5 &&    // the rounded size is good enough if s is > 4/5th of it
           spec_objallocs[entry_size].live > specialize_count(preset_entry_size(entry_size));
}

static struct redim_array *spec_objalloc_for_size(size_t entry_size, char const *requestor)
{
    assert(entry_size < NB_ELEMS(spec_objallocs));

    // first check for a specialized version
    if (spec_objallocs[entry_size].ra) return spec_objallocs[entry_size].ra;

    if (should_specialize_for_size(entry_size)) {
        spec_objallocs[entry_size].ra = malloc(sizeof(*spec_objallocs[entry_size].ra));
        if (spec_objallocs[entry_size].ra) {
            SLOG(LOG_NOTICE, "Specializing allocator for %s (%zu bytes)", requestor, entry_size);
            redim_array_ctor(spec_objallocs[entry_size].ra, preset_entry_size(entry_size), entry_size, requestor);
            return spec_objallocs[entry_size].ra;
        }
    }

    return NULL;
}

static struct redim_array *preset_objalloc_for_size(size_t entry_size, char const *requestor)
{
    unsigned s = ceil_log_2(entry_size);

    entry_size = ((size_t)1)<<s;

    static size_t obj_size_max = 0;   // max size used
    if (entry_size > obj_size_max) {
        obj_size_max = entry_size;
        SLOG(LOG_NOTICE, "Max obj size is now %zu (asked for %s)", entry_size, requestor);
    }

    assert(s < NB_ELEMS(fixed_objallocs));

    return &fixed_objallocs[s].ra;
}

/*
 * Alloc/Free
 */

/* We store the address of the redim_array along with the object, so that
 * objfree:
 * - does not have to compute which objalloc to free the object from
 * - does not have to know what size was allocated (like stdlib's free),
 *   so we can choose to specialize or not the objalloc (beware that
 *   between the free and the alloc we might have changed the policy
 *   regarding this size!) */
struct obj {
    struct redim_array *ra; // where bit 0 is set to 1 if it's not specialized
    char userdata[];
};

struct preset_obj {
    size_t spec_size;   // the size of this slot if it were specialized (ie. size of its struct obj)
    struct obj obj;
};

void *objalloc(size_t entry_size, char const *requestor)
{
    CHECK_LAST_FIELD(preset_obj, obj, struct obj);

    size_t spec_size = entry_size + sizeof(struct obj);
    struct redim_array *ra;
    
    if (spec_size < NB_ELEMS(spec_objallocs)) {
        ra = spec_objalloc_for_size(spec_size, requestor);
        if (ra) {
            // we have a specialized container, all is well
            struct obj *obj = redim_array_get(ra);
            if (! obj) return NULL;
            obj->ra = ra;
            return obj->userdata;
        }
    }
    
    // use a preset allocator then
    ra = preset_objalloc_for_size(entry_size + sizeof(struct preset_obj), requestor);
    assert(ra);
    struct preset_obj *p_obj = redim_array_get(ra);
    if (! p_obj) return NULL;
    p_obj->spec_size = spec_size;
    p_obj->obj.ra = (void *)(((intptr_t)ra) | 1); // so that we will recognize it as such when freeing
    if (spec_size < NB_ELEMS(spec_objallocs)) spec_objallocs[spec_size].live ++;
    return p_obj->obj.userdata;
}

void objfree(void *ptr)
{
    struct obj *obj = DOWNCAST(ptr, userdata, obj);
    assert(obj->ra);
    if ((intptr_t)obj->ra & 1) {    // unspecialized redim_array
        struct preset_obj *p_obj = DOWNCAST(obj, obj, preset_obj);
        if (p_obj->spec_size < NB_ELEMS(spec_objallocs)) {
            assert(spec_objallocs[p_obj->spec_size].live > 0);
            spec_objallocs[p_obj->spec_size].live --;
        }
        redim_array_free((void *)((intptr_t)p_obj->obj.ra^1), p_obj);
    } else {
        redim_array_free(obj->ra, obj);
    }
}


char *objalloc_strdup(char const *str)
{
    size_t len = strlen(str) + 1;
    char *str2 = objalloc(len, "strdups");
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
        int err = redim_array_ctor(&fixed_objallocs[f].ra, preset_entry_size(entry_size), entry_size, fixed_objallocs[f].name);
        assert(!err);
    }

    for (unsigned f = 0; f < NB_ELEMS(spec_objallocs); f++) {
        spec_objallocs[f].ra = NULL;
        spec_objallocs[f].live = 0;
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
    }

    log_category_objalloc_fini();

    redim_array_fini();
}

