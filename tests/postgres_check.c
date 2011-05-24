// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#undef NDEBUG
#include <assert.h>
#include <junkie/cpp.h>
#include <junkie/proto/pkt_wait_list.h>
#include <junkie/proto/cap.h>
#include <junkie/proto/ip.h>
#include <junkie/proto/eth.h>
#include <junkie/proto/tcp.h>
#include "lib.h"
#include "proto/postgres.c"

static void fetch_nb_rows_check(void)
{
    static struct nbr_test {
        char const *result;
        enum proto_parse_status expected_status;
        unsigned expected_nb_rows;
    } tests[] = {
        { "INSERT 16",  PROTO_OK, 16 },
        { "UPDATE 1",   PROTO_OK, 1 },
        { "INSERT 666", PROTO_OK, 666 },
        { "INSERT",     PROTO_PARSE_ERR, 0 },
        { "",           PROTO_PARSE_ERR, 0 },
        { "INSERT 23X", PROTO_PARSE_ERR, 0 },
    };

    for (unsigned t = 0; t < NB_ELEMS(tests); t++) {
        struct nbr_test const *const test = tests+t;
        unsigned nb_rows = -1;
        enum proto_parse_status status = fetch_nb_rows(test->result, &nb_rows);
        assert(status == test->expected_status);
        if (status == PROTO_OK) {
            assert(nb_rows == test->expected_nb_rows);
        }
    }
}

int main(void)
{
    log_init();
    proto_init();
    pkt_wait_list_init();
    ref_init();
    cap_init();
    eth_init();
    ip_init();
    ip6_init();
    tcp_init();
    postgres_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("postgres_check.log");

    fetch_nb_rows_check();

    postgres_fini();
    tcp_fini();
    ip6_fini();
    ip_fini();
    eth_fini();
    cap_fini();
    ref_fini();
    pkt_wait_list_fini();
    proto_fini();
    log_fini();
    return EXIT_SUCCESS;
}

