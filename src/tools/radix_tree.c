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
#include "junkie/tools/string.h"  // for tolower_ascii
#include "junkie/tools/objalloc.h"
#include "junkie/tools/radix_tree.h"

#define RADIX_MAX_CAPA 16

struct radix_node {
    char c1, c2;
    void *data; // set if this node can be a leaf
    unsigned num_children;
    struct radix_node *children[];
};

/*
 * Construction (empty)
 */

static void radix_node_ctor(struct radix_node *node, char c, bool case_sensitive, void *data, unsigned capa)
{
    node->c1 = c;
    node->c2 = case_sensitive ? c : changecase_ascii(c);
    node->data = data;
    node->num_children = capa;
    for (unsigned i = 0; i < capa; i ++) {
        node->children[i] = NULL;
    }
}

static struct radix_node *radix_node_new(char c, bool case_sensitive, void *data, unsigned capa)
{
    size_t sz = sizeof(struct radix_node) + capa * sizeof(struct radix_node*);
    struct radix_node *node = objalloc(sz, "radix_node");
    if (! node) return NULL;
    radix_node_ctor(node, c, case_sensitive, data, capa);
    return node;
}

void radix_tree_ctor(struct radix_tree *tree, bool case_sensitive)
{
    tree->root = radix_node_new('\0', case_sensitive, NULL, RADIX_MAX_CAPA);
}

struct radix_tree *radix_tree_new(bool case_sensitive)
{
    struct radix_tree *tree = objalloc(sizeof(*tree), "radix_tree");
    radix_tree_ctor(tree, case_sensitive);
    return tree;
}

static void radix_node_del(struct radix_node *);
static void radix_node_dtor(struct radix_node *node)
{
    for (unsigned i = 0; i < node->num_children; i ++) {
        radix_node_del(node->children[i]);
    }
}

static void radix_node_del(struct radix_node *node)
{
    radix_node_dtor(node);
    objfree(node);
}

void radix_tree_dtor(struct radix_tree *tree)
{
    radix_node_del(tree->root);
}

void radix_tree_del(struct radix_tree *tree)
{
    radix_tree_dtor(tree);
    objfree(tree);
}

/*
 * Add strings (before the radix_tree is compacted!)
 */

static void radix_node_append(struct radix_node *node, bool case_sensitive, char const *s, size_t len, void *data)
{
    if (0 == len) {
        assert(!node->data); // Or we added twice the same string
        node->data = data;
        return;
    }

    // Look for a continuation or a free children:
    int first_unset = -1;
    for (unsigned i = 0; i < node->num_children; i ++) {
        if (!node->children[i]) {
            if (first_unset < 0) first_unset = i;
        } else {
            if (*s == node->children[i]->c1 || *s == node->children[i]->c2) {
                // *s can not appear elsewhere
                radix_node_append(node->children[i], case_sensitive, s+1, len-1, data);
                return;
            }
        }
    }

    assert(first_unset >= 0);   // Or RADIX_MAX_CAPA is too small

    node->children[first_unset] = radix_node_new(*s, case_sensitive, NULL, RADIX_MAX_CAPA);
    assert(node->children[first_unset]);
    radix_node_append(node->children[first_unset], case_sensitive, s+1, len-1, data);
}

void radix_tree_add(struct radix_tree *tree, char const *s, size_t len, void *data)
{
    radix_node_append(tree->root, tree->case_sensitive, s, len, data);
}

void radix_tree_compact(struct radix_tree *tree)
{
    // TODO
    (void)tree;
}

/*
 * Search
 */

// Assume s matched up to that node, keep searching until reaching the end of s
static void *radix_node_find(struct radix_node const *node, bool case_sensitive, char const *s, size_t max_len, size_t plen, size_t *prefix_len)
{
    if (node->data) {
        if (prefix_len) *prefix_len = plen;
        return node->data;
    }
    if (0 == max_len) return TOO_SHORT;

    for (unsigned i = 0; i < node->num_children; i ++) {
        if (node->children[i] == NULL) break;    // TODO: after compact, assert!
        if (*s == node->children[i]->c1 || *s == node->children[i]->c2) {
            return radix_node_find(node->children[i], case_sensitive, s+1, max_len-1, plen+1, prefix_len);
        }
        // TODO: order the children in alpha order so we can stop early
        // (dichotomy search looks too complicated for the few collisions we will have)
    }
    return NOT_FOUND;
}

void *radix_tree_find(struct radix_tree const *tree, char const *s, size_t max_len, size_t *prefix_len)
{
    return radix_node_find(tree->root, tree->case_sensitive, s, max_len, 0, prefix_len);
}

/*
 * Init
 */

void radix_tree_init(void)
{
    objalloc_init();
}

void radix_tree_fini(void)
{
    objalloc_fini();
}
