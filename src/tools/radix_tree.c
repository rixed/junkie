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
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include "junkie/tools/string.h"  // for tolower_ascii
#include "junkie/tools/objalloc.h"
#include "junkie/tools/radix_tree.h"
#include "junkie/tools/log.h"

#define RADIX_MAX_CAPA 16
#define RADIX_MAX_LENGTH 32

struct radix_node {
    char s[RADIX_MAX_LENGTH];    // the string at this node
    unsigned len;
    void *data; // set if this node can be a leaf
    unsigned num_children;
    struct radix_node *children[];
};

/*
 * Construction (empty)
 */

static void radix_node_ctor(struct radix_node *node, char c, void *data, unsigned capa)
{
    node->s[0] = c;
    node->len = c = '\0' ? 0 : 1;
    node->data = data;
    node->num_children = capa;
    for (unsigned i = 0; i < capa; i ++) {
        node->children[i] = NULL;
    }
}

static struct radix_node *radix_node_new(char c, void *data, unsigned capa)
{
    size_t sz = sizeof(struct radix_node) + capa * sizeof(struct radix_node *);
    struct radix_node *node = objalloc(sz, "radix_node");
    if (! node) return NULL;
    radix_node_ctor(node, c, data, capa);
    return node;
}

void radix_tree_ctor(struct radix_tree *tree, bool case_sensitive)
{
    tree->root = radix_node_new('\0', NULL, RADIX_MAX_CAPA);
    tree->case_sensitive = case_sensitive;
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
            if (0 == (case_sensitive ? strncmp : strncasecmp)
                        (s, node->children[i]->s, node->children[i]->len)) {
                // *s can not appear elsewhere
                radix_node_append(node->children[i], case_sensitive, s+1, len-1, data);
                return;
            }
        }
    }

    assert(first_unset >= 0);   // Or RADIX_MAX_CAPA is too small

    node->children[first_unset] = radix_node_new(*s, NULL, RADIX_MAX_CAPA);
    assert(node->children[first_unset]);
    radix_node_append(node->children[first_unset], case_sensitive, s+1, len-1, data);
}

void radix_tree_add(struct radix_tree *tree, char const *s, size_t len, void *data)
{
    radix_node_append(tree->root, tree->case_sensitive, s, len, data);
}

static void radix_node_dump(struct radix_node const *node, unsigned depth)
{
    static char spaces[] = "                             ";
    assert(depth < sizeof(spaces));
    char *indent = spaces + (sizeof(spaces) - depth - 1);
    SLOG(LOG_DEBUG, "%snode@%p: %.*s", indent, node, node->len, node->s);
    for (unsigned i = 0; i < node->num_children; i ++) {
        radix_node_dump(node->children[i], depth + 1);
    }
}

void radix_tree_dump(struct radix_tree const *tree)
{
    radix_node_dump(tree->root, 0);
}

/* "Horizontal" compaction: keep only the required children. */
static void radix_node_compact_h(struct radix_node *node)
{
    for (unsigned i = 0; i < node->num_children; i ++) {
        if (node->children[i]) {
            radix_node_compact_h(node->children[i]);
        } else {
            node->num_children = i;
            return;
        }
    }
}

/* "Vertical" compaction: make the tree shallower by aggregating nodes with
 * only one child into a single string: */
static void radix_node_compact_v(struct radix_node *node)
{
    // Compact the children first
    for (unsigned i = 0; i < node->num_children; i ++) {
        radix_node_compact_v(node->children[i]);
    }

    while (!node->data && node->num_children == 1) {
        struct radix_node *child = node->children[0];
        memcpy(node->s + node->len, child->s, child->len);
        node->len += child->len;
        assert(node->len < RADIX_MAX_LENGTH);
        node->data = child->data;
        node->num_children = child->num_children;
        for (unsigned i = 0; i < child->num_children; i ++) {
            node->children[i] = child->children[i];
        }
        child->num_children = 0;
        radix_node_del(child);
    }
}

void radix_tree_compact(struct radix_tree *tree)
{
    radix_node_compact_h(tree->root);
    radix_node_compact_v(tree->root);
    radix_tree_dump(tree);
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
        assert(node->children[i]);
        size_t const len = MIN(max_len, node->children[i]->len);
        if (0 == (case_sensitive ? strncmp : strncasecmp)
                    (s, node->children[i]->s, len)) {
            if (len < node->children[i]->len) return TOO_SHORT;
            return radix_node_find(node->children[i], case_sensitive,
                                   s + len, max_len - len, plen + len, prefix_len);
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
