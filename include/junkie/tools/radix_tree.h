// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef RADIX_TREE_H_190702
#define RADIX_TREE_H_190702
#include <stdbool.h>

/** @file
 * @brief simple radix tree implementation to speed up substring searches
 */

struct radix_node;

struct radix_tree {
    struct radix_node *root;
    bool case_sensitive;
};

void radix_tree_ctor(struct radix_tree *, bool case_sensitive);
struct radix_tree *radix_tree_new(bool case_sensitive);

void radix_tree_add(struct radix_tree *, char const *, size_t, void *data);
void radix_tree_compact(struct radix_tree *);

void radix_tree_dump(struct radix_tree const *);

/* Look for one of the strings at the beginning of the given string.
 * The given size is the max length of the string. If we match so far
 * without reaching the end of a known prefix, return TOO_SHORT.
 * If no known prefix matches, return NOT_FOUND.
 * Otherwise, return the first data encountered (ie. shorter suffix) */
#define NOT_FOUND NULL
#define TOO_SHORT ((void *)1)
void *radix_tree_find(struct radix_tree const *, char const *, size_t max_len, size_t *prefix_len);

void radix_tree_dtor(struct radix_tree *);
void radix_tree_del(struct radix_tree *);

void radix_tree_init(void);
void radix_tree_fini(void);

#endif
