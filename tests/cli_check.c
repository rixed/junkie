// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#undef NDEBUG
#include <assert.h>
#include <string.h>
#include "tools/cli.c"

static void check_cli_2_enum(void)
{
    assert(-1 == cli_2_enum(false, "glip", "pas glop", "glop", "glup", "glops", NULL));
    assert(-1 == cli_2_enum(true,  "glip", "pas glop", "glop", "glup", "glops", NULL));
    assert( 1 == cli_2_enum(false, "glop", "pas glop", "glop", "glup", "glops", NULL));
    assert( 1 == cli_2_enum(true,  "glop", "pas glop", "glop", "glup", "glops", NULL));
    assert(-1 == cli_2_enum(true,  "glop", NULL));
    assert(-1 == cli_2_enum(true,  "GLOP", "pas glop", "glop", NULL));
    assert( 1 == cli_2_enum(false, "GLOP", "pas glop", "glop", NULL));
}

static void check_enum_2_str(void)
{
    char const *values = "glop|glop glop|pas glop";
    assert(NULL == cli_enum_2_str(10, values));
    assert(NULL == cli_enum_2_str(3, values));
    assert(NULL == cli_enum_2_str(1, ""));
    assert(0 == strcmp(cli_enum_2_str(0, values), "glop"));
    assert(0 == strcmp(cli_enum_2_str(1, values), "glop glop"));
    assert(0 == strcmp(cli_enum_2_str(2, values), "pas glop"));
    assert(0 == strcmp(cli_enum_2_str(0, "0|1|2"), "0"));
    assert(0 == strcmp(cli_enum_2_str(1, "0|1|2"), "1"));
    assert(0 == strcmp(cli_enum_2_str(2, "0|1|2"), "2"));
}

int main(void)
{
    log_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("cli_check.log");

    check_cli_2_enum();
    check_enum_2_str();

    log_fini();
    return EXIT_SUCCESS;
}

