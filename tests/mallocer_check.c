// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#include <stdio.h>
#undef NDEBUG
#include <assert.h>
#include <junkie/cpp.h>
#include <junkie/tools/mallocer.h>
#include <junkie/tools/log.h>

static void assert_empty(struct mallocer *mallocer)
{
    assert(mallocer->nb_blocks == 0);
    assert(mallocer->tot_size == 0);
}

static void malloc_check(void)
{
    MALLOCER(test1);
    assert_empty(&mallocer_test1);
    // Can malloc and deref
    char *ptr = MALLOC(test1, 1);
    assert(ptr);
    ptr[1] = 'a';
    assert(mallocer_test1.tot_size == 1);
    assert(mallocer_test1.nb_blocks == 1);
    FREE(ptr);
    assert_empty(&mallocer_test1);

    // Can malloc(0) then free it
    ptr = MALLOC(test1, 0);
    FREE(ptr);
    assert_empty(&mallocer_test1);
}

static void realloc_check(void)
{
    MALLOCER(test2);
    // Can resize down
    char *ptr = MALLOC(test2, 2);
    assert(ptr);
    ptr = REALLOC(test2, ptr, 1);
    assert(ptr);
    FREE(ptr);
    assert_empty(&mallocer_test2);

    // Resize to 0 means free
    ptr = MALLOC(test2, 1);
    REALLOC(test2, ptr, 0);
    assert_empty(&mallocer_test2);

    // Realloc of NULL means alloc
    ptr = REALLOC(test2, NULL, 1);
    assert(ptr);
    assert(mallocer_test2.tot_size == 1);
    FREE(ptr);
    assert_empty(&mallocer_test2);
}

int main(void)
{
    log_init();
    mallocer_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("mallocer_check.log");

    malloc_check();
    realloc_check();

    mallocer_fini();
    log_fini();

    return EXIT_SUCCESS;
}
