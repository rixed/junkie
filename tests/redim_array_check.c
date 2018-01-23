// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#undef NDEBUG
#include <assert.h>
#include <junkie/tools/ext.h>
#include <junkie/tools/objalloc.h>
#include <junkie/tools/mutex.h>
#include <junkie/tools/queue.h>
#include "tools/redim_array.c"

static void check_empty(void)
{
    struct redim_array ra;
    assert(0 == redim_array_ctor(&ra, 5000, 1, __func__));
    assert(0 == ra.nb_used);
    assert(0 == redim_array_foreach(&ra, NULL));
    redim_array_foreach(&ra, NULL); // must not call NULL
    redim_array_clear(&ra);
    redim_array_dtor(&ra);
}

static unsigned global_count = 0;
static int count(struct redim_array unused_ *ra, void unused_ *cell, va_list unused_ ap)
{
    global_count++;
    return 0;
}

static void check_ra(struct redim_array *ra)
{
    assert(ra->nb_malloced >= ra->nb_used);
    assert(ra->nb_used >= ra->nb_holes);
}

struct my_obj {
    LIST_ENTRY(my_obj) entry;
    unsigned value;
};
static LIST_HEAD(my_objs, my_obj) my_objs;

#define MAGIC_VALUE 0x28011976U
static void push_obj(struct redim_array *ra)
{
    struct my_obj *obj = redim_array_get(ra);
    assert(obj);
    obj->value = MAGIC_VALUE;
    LIST_INSERT_HEAD(&my_objs, obj, entry);
}

static void free_obj(struct redim_array *ra, struct my_obj *obj)
{
    LIST_REMOVE(obj, entry);
    obj->value = 0;
    redim_array_free(ra, obj);
}

static void free_random_obj(struct redim_array *ra)
{
    unsigned nb_not_free = ra->nb_used - ra->nb_holes;
    unsigned del_idx = rand() % nb_not_free;
    struct redim_array_chunk *chunk;
    TAILQ_FOREACH(chunk, &ra->chunks, entry) {
        unsigned nf = chunk->nb_used - chunk->nb_holes;
        if (del_idx < nf) {
            // look in this chunk
            for (unsigned n = 0; n < chunk->nb_used; n++) {
                struct my_obj *obj = chunk_entry(chunk, n);
                if (obj->value == MAGIC_VALUE) {
                    if (! del_idx--) {
                        free_obj(ra, obj);
                        return;
                    }
                }
            }
        } else {
            del_idx -= nf;
        }
    }
}

static void check_stress(unsigned nb_entries, unsigned alloc_size)
{
    struct redim_array ra;

    assert(0 == redim_array_ctor(&ra, alloc_size, sizeof(struct my_obj), __func__));

    // insert some entries
    LIST_INIT(&my_objs);
    for (unsigned e=0; e < nb_entries; e++) push_obj(&ra);
    assert(nb_entries == ra.nb_used);
    assert(ra.nb_holes == 0);
    check_ra(&ra);

    // count them
    global_count = 0;
    redim_array_foreach(&ra, count);
    assert(global_count == nb_entries);
    assert(ra.nb_holes == 0);
    check_ra(&ra);

    // clear them
    redim_array_clear(&ra);
    assert(ra.nb_used == 0);
    assert(ra.nb_holes == 0);
    check_ra(&ra);

    // reinsert
    LIST_INIT(&my_objs);
    for (unsigned e=0; e < nb_entries; e++) push_obj(&ra);
    assert(nb_entries == ra.nb_used);
    assert(ra.nb_holes == 0);
    check_ra(&ra);

    // clear by freeing all
    struct my_obj *obj;
    while (NULL != (obj = LIST_FIRST(&my_objs))) {
        free_obj(&ra, obj);
    }
    assert(ra.nb_used == 0);
    assert(ra.nb_holes == 0);
    assert(ra.nb_malloced == 0);
    check_ra(&ra);

    // reinsert with intermediate deletions
    unsigned nb_pop = 0, nb_push = 0;
    for (unsigned e=0; e < nb_entries*3; e++) {
        if (nb_push > nb_pop && (rand() & 0x30) == 0) {
            free_random_obj(&ra);
            nb_pop++;
        } else {
            push_obj(&ra);
            nb_push++;
        }
    }
    check_ra(&ra);

    // display compactness
    printf("Compactness after %u additions and %u deletions: %3.3f%%\n",
        nb_push, nb_pop, 100. * (ra.nb_used - ra.nb_holes) / ra.nb_malloced);

    redim_array_dtor(&ra);
}

int main(void)
{
    log_init();
    mutex_init();
    ext_init();
    objalloc_init();
    redim_array_init();
    log_set_level(LOG_INFO, NULL);
    log_set_file("redim_array_check.log");

    check_empty();
    check_stress(10, 1);
    check_stress(100, 10);
    check_stress(1000, 100);
    check_stress(10000, 1000);
    check_stress(100000, 1000);

    redim_array_fini();
    objalloc_fini();
    ext_fini();
    mutex_fini();
    log_fini();
    return EXIT_SUCCESS;
}

