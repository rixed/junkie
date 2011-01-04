// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <junkie/tools/miscmacs.h>
#include "tools/files.c"

static void mkdir_all_check(void)
{
    // Check errors are reported
    assert(-1 == mkdir_all("/no/permission", false));

    // Checks multiple / are coallesced
    char *tmp = tempnam("/tmp", "files_check");
    assert(tmp);
    assert(0 == mkdir_all(tempstr_printf("%s///y//z", tmp), false));
    assert(0 == system(tempstr_printf("rm -rf %s", tmp)));
}

static unsigned lineno;
static struct line_desc {
    size_t len;
    char first, last;
} const lines_desc[] = {
    { 0, '\0', '\0', }, { 1, '1', '1' }, { 2, '2', 'a' }, { 3, '3', 'c' },
    { 0, '\0', '\0', }, { 1, '1', '1' }, { 0, '\0', '\0' },
    { 2047, 'x', 'c', },
};

static int line_cb(char *line, size_t len, va_list ap)
{
    SLOG(LOG_DEBUG, "Checking line '%s' of length %zu", line, len);
    int one = va_arg(ap, int);
    assert(one == 1);
    assert(lineno < NB_ELEMS(lines_desc));
    struct line_desc const *desc = lines_desc + lineno;
    assert(len == desc->len);
    if (len > 0) {
        assert(line[0] == desc->first);
        assert(line[len-1] == desc->last);
    }
    lineno ++;
    return 0;
}

static void foreach_line_check(void)
{
    int err = file_foreach_line(STRIZE(SRCDIR) "/foreach.txt", line_cb, 1);
    assert(! err);
}

int main(void)
{
    log_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("files_check.log");

    mkdir_all_check();
    foreach_line_check();

    log_fini();
    return EXIT_SUCCESS;
}
