// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#undef NDEBUG
#include <assert.h>
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

int main(void)
{
    log_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("cli_check.log");

    check_cli_2_enum();

    log_fini();
    return EXIT_SUCCESS;
}

