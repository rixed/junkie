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
 * in order to rduce fragmentation even more. Since redim_arrays
 * are constructed without any chunk these objallocators takes no
 * RAM until used, though. */
struct redim_array *objalloc_for_size(size_t entry_size);

/* We store the address of the redim_array along with the object, so that
 * objfree:
 * - does not have to compute which objalloc to free the object from
 * - does not have to know what size was allocated (like stdlib's free),
 *   so we can choose to specialize or not the objalloc. */
struct preset_obj {
    struct redim_array *ra;
    char userdata[];
};

#include <assert.h>
static inline void *objalloc(size_t entry_size)
{
    entry_size += sizeof(struct preset_obj);
    struct redim_array *ra = objalloc_for_size(entry_size);
    assert(ra);
    struct preset_obj *p_obj = redim_array_get(ra);
    if (p_obj) {
        p_obj->ra = ra;
        return p_obj->userdata;
    } else {
        return NULL;
    }
}

static inline void objfree(void *obj)
{
    struct preset_obj *p_obj = DOWNCAST(obj, userdata, preset_obj);
    assert(p_obj->ra);
    redim_array_free(p_obj->ra, p_obj);
}

char *objalloc_strdup(char const *);

void objalloc_init(void);
void objalloc_fini(void);

#endif
