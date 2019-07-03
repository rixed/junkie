// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2018, SecurActive.
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
#include <stdlib.h>
#include <stdarg.h>
#include "junkie/tools/ext.h"
#include "junkie/tools/objalloc.h"
#include "junkie/tools/log.h"
#include "junkie/tools/miscmacs.h"
#include "junkie/tools/hash.h"

struct hashes hashes = LIST_HEAD_INITIALIZER(hashes);

/*
 * Extensions
 */

static struct ext_function sg_hash_names;
static SCM g_hash_names(void)
{
    SCM ret = SCM_EOL;
    struct hash_base *hash;
    LIST_FOREACH(hash, &hashes, entry) {
        ret = scm_cons(scm_from_latin1_string(hash->name), ret);
    }
    return ret;
}

static struct hash_base *hash_of_scm_name(SCM name_)
{
    char *name = scm_to_tempstr(name_);
    struct hash_base *hash;
    LIST_LOOKUP(hash, &hashes, entry, 0 == strcasecmp(name, hash->name));
    return hash;
}

static SCM num_lists_sym;
static SCM num_lists_min_sym;
static SCM num_entries_sym;
static SCM num_entries_max_sym;
static SCM num_rehash_sym;

static struct ext_function sg_hash_stats;
static SCM g_hash_stats(SCM name_)
{
    struct hash_base *hash = hash_of_scm_name(name_);
    if (! hash) return SCM_UNSPECIFIED;

    return scm_list_5(
        // See g_proto_stats
        scm_cons(num_lists_sym, scm_from_uint(hash->num_lists)),
        scm_cons(num_lists_min_sym, scm_from_uint(hash->num_lists_min)),
        scm_cons(num_entries_sym, scm_from_uint(hash->size)),
        scm_cons(num_entries_max_sym, scm_from_uint(hash->max_size)),
        scm_cons(num_rehash_sym, scm_from_uint(hash->num_rehash)));
}

extern inline uint_least32_t hashfun(void const *key, size_t len);

static unsigned inited;
void hash_init(void)
{
    if (inited++) return;
    ext_init();
    objalloc_init();

    num_lists_sym       = scm_permanent_object(scm_from_latin1_symbol("num-lists"));
    num_lists_min_sym   = scm_permanent_object(scm_from_latin1_symbol("num-lists-min"));
    num_entries_sym     = scm_permanent_object(scm_from_latin1_symbol("num-entries"));
    num_entries_max_sym = scm_permanent_object(scm_from_latin1_symbol("num-entries-max"));
    num_rehash_sym      = scm_permanent_object(scm_from_latin1_symbol("num-rehash"));

    ext_function_ctor(&sg_hash_names,
        "hash-names", 0, 0, 0, g_hash_names,
        "(hash-names): returns the list of defined hashes.\n");

    ext_function_ctor(&sg_hash_stats,
        "hash-stats", 1, 0, 0, g_hash_stats,
        "(hash-stats \"hash-name\"): returns some statistics about this hash, such as current number of elements.\n"
        "See also (? 'hash-names) for a list of hash names.\n");
}

void hash_fini(void)
{
    if (--inited) return;

    objalloc_fini();
    ext_fini();
}
