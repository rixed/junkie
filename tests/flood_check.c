// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#undef NDEBUG
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include <junkie/cpp.h>
#include <junkie/tools/objalloc.h>
#include <junkie/tools/ext.h>
#include <junkie/proto/pkt_wait_list.h>
#include <junkie/proto/cap.h>
#include <junkie/proto/eth.h>
#include <junkie/proto/ip.h>
#include <junkie/proto/udp.h>
#include "lib.h"

static void flood_check(unsigned num)
{
    mux_proto_ip.num_max_children = 10;
    struct timeval now;
    timeval_set_now(&now);
    struct parser *ip_parser = proto_ip->ops->parser_new(proto_ip);
    assert(ip_parser);

    uint8_t packet[2048];
    for (unsigned t = 0; t < num; t++) {
        size_t len = rand() % sizeof(packet);
        if (! udp_ctor_random(packet, len)) continue;
        (void)ip_parser->proto->ops->parse(ip_parser,  NULL, 0, packet, len, len, &now, len, packet);
    }

    SLOG(LOG_INFO, "Number of UDP parsers : %u", proto_udp->num_parsers);
    fflush(stdout);
    assert(proto_udp->num_parsers < 20); // Limiting the number of children is a best effort attempt

    parser_unref(&ip_parser);
}

int main(void)
{
    log_init();
    mutex_init();
    ext_init();
    objalloc_init();
    pkt_wait_list_init();
    ref_init();
    cap_init();
    eth_init();
    ip_init();
    ip6_init();
    udp_init();
    log_set_level(LOG_CRIT, NULL);
    log_set_file("flood_check.log");

    flood_check(100);

    doomer_stop();
    udp_fini();
    ip6_fini();
    ip_fini();
    eth_fini();
    cap_fini();
    ref_fini();
    pkt_wait_list_fini();
    objalloc_fini();
    ext_fini();
    mutex_fini();
    log_fini();
    return EXIT_SUCCESS;
}

