// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#include <stdio.h>
#undef NDEBUG
#include <assert.h>
#include <time.h>
#include <stdint.h>
#include <sys/time.h>
#include <junkie/cpp.h>
#include <junkie/tools/ext.h>
#include <junkie/tools/tempstr.h>
#include <junkie/tools/objalloc.h>
#include "tools/hash.c"

struct h_value {
    HASH_ENTRY(h_value) entry;
    unsigned value;
};

static struct h_value *v_new(unsigned val)
{
    struct h_value *v = malloc(sizeof(*v));
    assert(v);
    v->value = val;
    return v;
}

HASH_TABLE(test_hash, h_value);

static void check_hash_size(struct test_hash *h, unsigned expected_size)
{
    assert(h->base.size == expected_size);
    unsigned count = 0;
    struct h_value *v;
    HASH_FOREACH(v, h, entry) count++;
    assert(count == expected_size);
}

static void hash_check(unsigned num_elem)
{
    struct test_hash h;
    HASH_INIT(&h, num_elem, "test");

    assert(HASH_EMPTY(&h));

    // Insert that many values
    for (unsigned i = 0; i < num_elem; i++) {
        struct h_value *v = v_new(i);
        HASH_INSERT(&h, v, &v->value, entry);
    }

    // Check we have num_elem elements
    check_hash_size(&h, num_elem);

    // Check we can each of them, once
    struct h_value *v;
    for (unsigned val = 0; val < num_elem; val++) {
        bool found = false;
        HASH_FOREACH_MATCH(v, &h, &val, value, entry) {
            assert(! found);
            found = true;
            assert(v->value == val);
        }
        assert(found);
    }

    // And that we can thus remove them
    struct h_value *tmp;
    HASH_FOREACH_SAFE(v, &h, entry, tmp) {
        HASH_REMOVE(&h, v, entry);
    }
    assert(0 == h.base.size);

    HASH_DEINIT(&h);
}

static void rehash_check(void)
{
    struct test_hash h;
    HASH_INIT(&h, 100, "test");
    struct h_value *v;

    v = v_new(1);
    HASH_INSERT(&h, v, &v->value, entry);
    v = v_new(2);
    HASH_INSERT(&h, v, &v->value, entry);
    v = v_new(3);
    HASH_INSERT(&h, v, &v->value, entry);
    assert(h.base.size == 3);

    // Now we have a hash that's too big. Let's resize :
    HASH_TRY_REHASH(&h, value, entry);
    assert(HASH_AVG_LENGTH(&h) >= HASH_LENGTH_MIN || h.base.num_lists <= h.base.num_lists_min);
    assert(HASH_AVG_LENGTH(&h) <= HASH_LENGTH_MAX);

    check_hash_size(&h, 3);

    // Now insert many elements
    for (unsigned i = 0; i < 10000; i++) {
        struct h_value *v = v_new(i);
        HASH_INSERT(&h, v, &v->value, entry);
    }

    // Grow it
    HASH_TRY_REHASH(&h, value, entry);
    assert(HASH_AVG_LENGTH(&h) >= HASH_LENGTH_MIN);
    assert(HASH_AVG_LENGTH(&h) <= HASH_LENGTH_MAX);

    check_hash_size(&h, 3 + 10000);

    // Empty the hash and quit
    struct h_value *tmp;
    HASH_FOREACH_SAFE(v, &h, entry, tmp) {
        HASH_REMOVE(&h, v, entry);
    }
    assert(h.base.size == 0);

    HASH_DEINIT(&h);

}

int main(void)
{
    log_init();
    ext_init();
    objalloc_init();
    hash_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("hash_check.log");

    hash_check(1);
    hash_check(10000);
    rehash_check();

    hash_fini();
    objalloc_fini();
    ext_fini();
    log_fini();
    return EXIT_SUCCESS;
}
