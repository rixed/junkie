// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#include <assert.h>
#include <junkie/cpp.h>
#include <junkie/proto/tcp.h>
#include "proto/tns.c"

static void net8_string_check(void)
{
    struct string_test {
        char *str;
        size_t len;
    } tests[] = {
        { "\012glop glop", 9 },
        { "\376\004pas \004glop", 8 },
        { "\376\004pas \004glop\004pas \004glop", 16 },
    };

    for (unsigned t = 0; t < NB_ELEMS(tests); t++) {
        struct string_test const *const test = tests+t;
        struct sql_proto_info info;
        struct cursor cursor;
        size_t len = strlen(test->str);
        cursor_ctor(&cursor, (uint8_t *)test->str, len+1);
        memset(&info, 0, sizeof(info));
        net8_copy_sql(&info, &cursor, 0);
        assert(info.set_values & SQL_SQL);
        assert(strlen(info.u.query.sql) == test->len);
    }
}

int main(void)
{
    log_init();
    proto_init();
    tcp_init();
    tns_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("oracle_check.log");

    net8_string_check();

    tns_fini();
    tcp_fini();
    proto_fini();
    log_fini();
    return EXIT_SUCCESS;
}

