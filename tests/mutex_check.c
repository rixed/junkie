// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#undef NDEBUG
#include <assert.h>
#include <junkie/tools/log.h>
#include "tools/mutex.c"

static struct supermutex super1, super2;

static void *deadlocker(void *dummy)
{
    (void)dummy;

    assert(0 == supermutex_lock(&super2));
    assert(0 == supermutex_lock(&super1));  // after some time...

    supermutex_unlock(&super1);
    supermutex_unlock(&super2);

    return NULL;
}

static void supermutex_check(void)
{
    printf("You should not wait more than one second in this deadlock detection check...\n");

    supermutex_ctor(&super1, "test1");
    supermutex_ctor(&super2, "test2");

    // Check I can take the mutex several times
    assert(0 == supermutex_lock(&super1));
    assert(0 == supermutex_lock(&super1));
    assert(0 == supermutex_lock(&super1));
    // And then release it that many times
    supermutex_unlock(&super1);
    supermutex_unlock(&super1);
    supermutex_unlock(&super1);
    assert(my_supermutex_user->nb_locks == 0);

    // Now check deadlock
    assert(0 == supermutex_lock(&super1));  // take super1
    pthread_t other_thread;
    pthread_create(&other_thread, NULL, deadlocker, NULL);
    sleep(1);   // wait for the other thread to grab super2 and wait for super1
    assert(supermutex_lock(&super2) == MUTEX_DEADLOCK);
    supermutex_unlock(&super1); // unblocks the other threads
    pthread_join(other_thread, NULL);

    supermutex_dtor(&super1);
}

int main(void)
{
    log_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("mutex_check.log");
    mutex_init();

    supermutex_check();

    mutex_fini();
    log_fini();
    return EXIT_SUCCESS;
}
