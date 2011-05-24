// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#undef NDEBUG
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include "tools/log.c"

// Test basic functionnalities
static void check_simple(void)
{
    char filename[] = "/tmp/junkie.check.XXXXXX";
    if (mktemp(filename)) {}    // Clean warn_unused_result, particularly useless since "The mktemp() function always returns template."
    assert(filename[0] != '\0');
    assert(0 == log_set_file(filename));

    off_t end = lseek(log_fd, 0, SEEK_END);
    log_set_level(LOG_DEBUG, NULL);
    SLOG(LOG_CRIT, "123");
    assert(lseek(log_fd, 0, SEEK_END) - end >= 4);

    log_set_level(LOG_INFO, NULL);
    end = lseek(log_fd, 0, SEEK_END);
    SLOG(LOG_DEBUG, "Won't show");
    assert(end == lseek(log_fd, 0, SEEK_END));

    // Check that setting logfile to NULL stops
    log_set_level(LOG_DEBUG, NULL);
    assert(0 == log_set_file(NULL));
    end = lseek(log_fd, 0, SEEK_END);
    SLOG(LOG_DEBUG, "Won't show");
    assert(end == lseek(log_fd, 0, SEEK_END));

    (void)unlink(filename);
}

// Setting log file to NULL must prevent logs (of lower prio than CRIT)
static void check_no_log(void)
{
    log_set_file(NULL);
    log_set_level(LOG_DEBUG, NULL);
    assert(NULL == log_get_file());
    SLOG(LOG_ERR, "Print this and die : '%s'", (char *)0x123);
}

// Set_log_file must create all required dirs
static void check_create_dir(void)
{
    char filename[PATH_MAX] = "/tmp/randomdir.XXXXXX";
    if (mktemp(filename)) {}
    assert(filename[0] != '\0');
    int const len = strlen(filename);
    strncat(filename, "/randomfile.XXXXXX", sizeof(filename) - len - 1);
    if (mktemp(filename)) {}
    assert(filename[len] != '\0');

    assert(0 == log_set_file(filename));

    (void)unlink(filename);
    filename[len] = '\0';
    assert(0 == rmdir(filename));
}

// Check we get what we set (even when we set nothing)
static void check_set_get(void)
{
    // Always valid
    assert(0 == log_set_file(NULL));
    assert(NULL == log_get_file());

    // Mere test
    char filename[PATH_MAX] = "/tmp/check.XXXXXX";
    if (mktemp(filename)) {}
    assert(filename[0] != '\0');
    assert(0 == log_set_file(filename));
    assert(0 == strcmp(log_get_file(), filename));
    assert(0 == unlink(filename));
}

int main(void)
{
    check_simple();
    check_no_log();
    check_create_dir();
    check_set_get();

    return EXIT_SUCCESS;
}

