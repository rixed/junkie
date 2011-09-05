// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#undef NDEBUG
#include <assert.h>
#include <junkie/tools/log.h>
#include "tools/mutex.c"

static void *deadlocker(void *super_)
{
    struct supermutex *super = super_;
    assert(supermutex_lock(super) == MUTEX_DEADLOCK);
    return NULL;
}

static void supermutex_check(void)
{
    struct supermutex super;
    supermutex_ctor(&super, "test");

    // Check I can take the mutex several times
    assert(0 == supermutex_lock(&super));
    assert(0 == supermutex_lock(&super));
    assert(0 == supermutex_lock(&super));
    // And then release it that many times
    supermutex_unlock(&super); assert(pthread_self() == super.owner);
    supermutex_unlock(&super); assert(pthread_self() == super.owner);
    supermutex_unlock(&super); assert(0 == super.owner);

    // Now check deadlock
    assert(0 == supermutex_lock(&super));
    pthread_t other_thread;
    pthread_create(&other_thread, NULL, deadlocker, &super);
    pthread_join(other_thread, NULL);

    supermutex_dtor(&super);
}

int main(void)
{
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("mutex_check.log");

    supermutex_check();

    return EXIT_SUCCESS;
}
