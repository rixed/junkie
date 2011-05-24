// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#include <stdio.h>
#undef NDEBUG
#include <assert.h>
#include <junkie/proto/ip.h>
#include <junkie/proto/port_muxer.h>

static void port_muxer_check(void)
{
    struct port_muxer_list muxers;
    struct port_muxer a, b, c, d;

    port_muxer_list_ctor(&muxers, "test");
    // Insert some port range in random order
    port_muxer_ctor(&a, &muxers, 10, 15, proto_ip);
    port_muxer_ctor(&b, &muxers, 10, 14, proto_ip);
    port_muxer_ctor(&c, &muxers, 17, 10, proto_ip); // also try inverting min and max
    port_muxer_ctor(&d, &muxers, 10, 16, proto_ip);
    // Check ordering
    unsigned last_port = 13;
    struct port_muxer *muxer;
    TAILQ_FOREACH(muxer, &muxers.muxers, entry) {
        assert(muxer->port_max > last_port);
        last_port = muxer->port_max;
    }
}

int main(void)
{
    log_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("port_range_check.log");

    port_muxer_check();

    log_fini();
    return EXIT_SUCCESS;
}

