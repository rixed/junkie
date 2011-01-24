// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include <junkie/cpp.h>
#include <junkie/tools/mallocer.h>
#include "lib.h"
#include "proto/ip.c"
#include "proto/udp.c"

static void flood_check(unsigned nb)
{
    mux_proto_ip.nb_max_children = 10;
    struct timeval now;
    timeval_set_now(&now);
    struct parser *ip_parser = proto_ip->ops->parser_new(proto_ip, &now);
    assert(ip_parser);

    uint8_t packet[2048];
    for (unsigned t = 0; t < nb; t++) {
        size_t len = rand() % sizeof(packet);
        if (! udp_ctor_random(packet, len)) continue;
        (void)ip_parser->proto->ops->parse(ip_parser,  NULL, 0, packet, len, len, &now, NULL, len, packet);
    }

    SLOG(LOG_INFO, "Number of UDP parsers : %u", proto_udp->nb_parsers);
    fflush(stdout);
    assert(proto_udp->nb_parsers < 20); // Limiting the nb of children is a best effort attempt

    parser_unref(ip_parser);
}

int main(void)
{
    log_init();
    mallocer_init();
    ip_init();
    udp_init();
    log_set_level(LOG_CRIT, NULL);
    log_set_file("flood_check.log");

    flood_check(100);

    udp_fini();
    ip_fini();
    mallocer_fini();
    log_fini();
    return EXIT_SUCCESS;
}

