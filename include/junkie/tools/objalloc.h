// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef OBJALLOC_H_111019
#define OBJALLOC_H_111019
#include <junkie/tools/redim_array.h>
#include <junkie/tools/mutex.h>
#include <junkie/tools/miscmacs.h>

/** @file
 * @brief An allocator for fixed-size objects to fight fragmentation.
 *
 * Use redim_arrays to implement a non-fragmenting allocator.
 */

/** We have some preset object allocator for many sizes of objects,
 * in order to reduce fragmentation even more. Since redim_arrays
 * are constructed without any chunk these objallocators takes no
 * RAM until used, though.
 * @param entry_size is the object size we want an allocator for.
 * @param requestor is used to name the allocator if one is created. */
void *objalloc(size_t entry_size, char const *requestor);
void objfree(void *);

char *objalloc_strdup(char const *);

void objalloc_init(void);
void objalloc_fini(void);

#endif
