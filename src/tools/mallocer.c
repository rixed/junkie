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
#include <assert.h>
#include <string.h>
#include <junkie/config.h>
#ifdef HAVE_MALLOC_H
#   include <malloc.h>
#endif
#include <junkie/tools/ext.h>
#include <junkie/tools/mallocer.h>
#include <junkie/tools/mutex.h>

static char const Id[] = "$Id: ad2fe95c8bace3f7f278f0b1bcfde0f0639cf1ba $";

struct mallocers mallocers = SLIST_HEAD_INITIALIZER(mallocers);
struct mutex mallocers_lock;

/*
 * Tools
 */

static void add_block(struct mallocer *mallocer, struct mallocer_block *block)
{
    PTHREAD_ASSERT_LOCK(&mallocer->mutex.mutex);
    LIST_INSERT_HEAD(&mallocer->blocks, block, entry);
    mallocer->tot_size += block->size;
    mallocer->nb_blocks ++;
}

static void rem_block(struct mallocer_block *block)
{
    PTHREAD_ASSERT_LOCK(&block->mallocer->mutex.mutex);
    assert(block->mallocer->nb_blocks > 0);
    assert(block->mallocer->tot_size >= block->size);
    LIST_REMOVE(block, entry);
    block->mallocer->tot_size -= block->size;
    block->mallocer->nb_blocks --;
}

/*
 * Alloc
 */

void *mallocer_alloc(struct mallocer *mallocer, size_t size)
{
    // FIXME: align return address to 16 bytes
    struct mallocer_block *block = malloc(sizeof(*block) + size);
    if (! block) return NULL;
    mutex_lock(&mallocer->mutex);
    block->size = size;
    block->date = time(NULL);
    block->mallocer = mallocer;
    block->mallocer->nb_allocs ++;
    add_block(mallocer, block);
    mutex_unlock(&mallocer->mutex);
    return block+1;
}

void *mallocer_realloc(struct mallocer *mallocer, void *ptr, size_t size)
{
    if (! ptr) return mallocer_alloc(mallocer, size);
    if (size == 0) {
        mallocer_free(ptr);
        return NULL;
    }

    struct mallocer_block *block = (struct mallocer_block *)ptr-1;

    mutex_lock(&mallocer->mutex);
    // We must first remove this block from the list, since it may be moved and the original one freed
    rem_block(block);

    struct mallocer_block *block2 = realloc(block, sizeof(*block2) + size);
    if (! block2) {
        // Put the original block back in the list
        LIST_INSERT_HEAD(&block->mallocer->blocks, block, entry);
        mutex_unlock(&mallocer->mutex);
        return NULL;
    }
    // Put the new block in the list and adjust size
    block2->size = size;
    add_block(mallocer, block2);
    mutex_unlock(&mallocer->mutex);
    return block2+1;
}

void mallocer_free(void *ptr)
{
    if (! ptr) return;

    struct mallocer_block *block = (struct mallocer_block *)ptr-1;
    mutex_lock(&block->mallocer->mutex);
    rem_block(block);
    mutex_unlock(&block->mallocer->mutex);

    free(block);
}

char *mallocer_strdup(struct mallocer *mallocer, char const *str)
{
    size_t len = strlen(str) + 1;
    char *str2 = mallocer_alloc(mallocer, len);
    if (! str2) return NULL;
    memcpy(str2, str, len);
    return str2;
}

/*
 * Extensions
 */

static struct ext_function sg_malloc_stats;
static SCM g_malloc_stats(void)
{
#   ifdef HAVE_MALLOC_STATS
    malloc_stats();
#   endif
#   ifdef HAVE_MALLINFO
    struct mallinfo info = mallinfo();
    // See g_proto_stats
#   define CELL(field, name) scm_cons(scm_from_locale_symbol(name), scm_from_int(info.field))
    return scm_list_n(
        CELL(arena, "sbrked-bytes"),
        CELL(ordblks, "unused-chunks"),
        CELL(smblks, "fastbin-chunks"),
        CELL(hblks, "mmaped-chunks"),
        CELL(hblkhd, "mmaped-bytes"),
        CELL(fsmblks, "freed-fastbin-bytes"),
        CELL(uordblks, "malloced-bytes"),
        CELL(fordblks, "freed-bytes"),
        CELL(keepcost, "topmost-free-bytes"),
        SCM_UNDEFINED);
#   undef CELL
#   else    // HAVE_MALLINFO
    return scm_list_n(SCM_UNDEFINED);
#   endif   // HAVE_MALLINFO
}

static struct ext_function sg_mallocer_names;
static SCM g_mallocer_names(void)
{
    SCM ret = SCM_EOL;
    struct mallocer *mallocer;
    SLIST_FOREACH(mallocer, &mallocers, entry) ret = scm_cons(scm_from_locale_string(mallocer->name), ret);
    return ret;
}

static struct mallocer *mallocer_of_scm_name(SCM name_)
{
    char *name = scm_to_tempstr(name_);
    struct mallocer *mallocer;
    SLIST_FOREACH(mallocer, &mallocers, entry) {
        if (0 == strncasecmp(name, mallocer->name, sizeof(name))) return mallocer;
    }
    return NULL;
}

static struct ext_function sg_mallocer_stats;
static SCM g_mallocer_stats(SCM name_)
{
    struct mallocer *mallocer = mallocer_of_scm_name(name_);
    if (! mallocer) return SCM_UNSPECIFIED;

    return scm_list_n(
        // See g_proto_stats
        scm_cons(scm_from_locale_symbol("tot-size"), scm_from_size_t(mallocer->tot_size)),
        scm_cons(scm_from_locale_symbol("nb-blocks"), scm_from_uint(mallocer->nb_blocks)),
        scm_cons(scm_from_locale_symbol("nb-allocs"), scm_from_uint(mallocer->nb_allocs)),
        SCM_UNDEFINED);
}

static SCM next_block(SCM list, struct mallocer_block *block)
{
    if (! block) return list;
    SCM alist = scm_list_n(
        scm_cons(scm_from_locale_symbol("start-address"), scm_from_size_t((size_t)block)),
        scm_cons(scm_from_locale_symbol("size"), scm_from_size_t(block->size)),
        scm_cons(scm_from_locale_symbol("date"), scm_from_uint((unsigned int)block->date)),
        SCM_UNDEFINED);

    return next_block(scm_cons(alist, list), LIST_NEXT(block, entry));
}

static struct ext_function sg_mallocer_blocks;
static SCM g_mallocer_blocks(SCM name_)
{
    struct mallocer *mallocer = mallocer_of_scm_name(name_);
    if (! mallocer) return SCM_UNSPECIFIED;

    return next_block(SCM_EOL, LIST_FIRST(&mallocer->blocks));
}

void mallocer_init(void)
{
    mutex_ctor(&mallocers_lock, "mallocers");

    ext_function_ctor(&sg_malloc_stats,
        "libc-mem-stats", 0, 0, 0, g_malloc_stats,
        "(libc-mem-stats) : display the equivalent of mallinfo.\n"
        "Note : malloced-bytes + free-bytes details the sbrked bytes. mmaped chunks are alloced and freed individually.\n");

    ext_function_ctor(&sg_mallocer_names,
        "mallocer-names", 0, 0, 0, g_mallocer_names,
        "(mallocer-names) : get the list of mallocers.\n"
        "See also (? 'mallocer-stats).\n");

    ext_function_ctor(&sg_mallocer_stats,
        "mallocer-stats", 1, 0, 0, g_mallocer_stats,
        "(mallocer-stats \"name\") : get stats about this mallocer.\n"
        "See also (? 'mallocer-names).\n");

    ext_function_ctor(&sg_mallocer_blocks,
        "mallocer-blocks", 1, 0, 0, g_mallocer_blocks,
        "(mallocer-blocks \"name\") : return detailed information on every blocks allocated by this mallocer.\n"
        "See also (? 'mallocer-names).\n");
}

void mallocer_fini(void)
{
    mutex_dtor(&mallocers_lock);
}
