// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef REDIM_ARRAY_H_100907
#define REDIM_ARRAY_H_100907
#include <stdarg.h>
#include <junkie/tools/queue.h>
#include <junkie/tools/mutex.h>

/** @file
 * @brief Redimentionable arrays
 *
 * In order to make good object allocator, each chunk of array comes
 * with its internal freelist, and empty chunks are deleted when empty.
 */

/** A redim_array is a redimentionable array.
 * Each time you hit it's lenght you can resize it, without much time penalty.
 * Performence are similar than a mere array if your initial size guess is valid
 * or similar to a mere list if your initial guess is too small.
 */
struct redim_array {
    unsigned nb_used;       ///< Number of used entries
    unsigned nb_malloced;   ///< Number of malloced entries
    unsigned nb_holes;      ///< Number of used entries freed by user (on the freelist)
    unsigned alloc_size;    ///< Initial guess of the array size (we are going to alloc chunks of this size)
    size_t entry_size;      ///< Size of a single value
    TAILQ_HEAD(redim_array_chunks, redim_array_chunk) chunks;   ///< List of array chunks
    struct mutex chunks_mutex;  ///< Mutex to protect the above chunks list
    LIST_ENTRY(redim_array) entry;  ///< Entry in the list of all redim_arrays
    char const *name;       ///< Name of the array, for stats purpose
};

/// Construct a new redim_array
int redim_array_ctor(struct redim_array *, unsigned alloc_size, size_t entry_size, char const *name);

/// Destruct a redim array
void redim_array_dtor(struct redim_array *);

/// We do not provide redim_array_pop because we don't want to return an address of an element that was removed from the array

/// @return the first reusable cell in the redim_array
void *redim_array_get(struct redim_array *);

/// Free this entry (and try to compact the redim_array by getting rid of empty chunks)
void redim_array_free(struct redim_array *, void *);

/// Empty the array.
void redim_array_clear(struct redim_array *);

/// Iterator
int redim_array_foreach(struct redim_array *, int (*cb)(struct redim_array *, void *cell, va_list), ...);

void redim_array_init(void);
void redim_array_fini(void);

#endif
