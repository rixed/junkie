// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2010, SecurActive.
 *
 * This file is part of Junkie.
 *
 * Junkie is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Junkie is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Junkie.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include "junkie/config.h"
#include "junkie/tools/log.h"
#include "junkie/tools/cli.h"
#include "junkie/tools/serialize.h"
#include "junkie/tools/sock.h"
#include "junkie/tools/ext.h"
#include "junkie/tools/mallocer.h"
#include "junkie/tools/redim_array.h"
#include "junkie/tools/mutex.h"
#include "junkie/tools/hash.h"
#include "junkie/cpp.h"
#include "junkie/proto/pkt_wait_list.h"
#include "junkie/proto/cap.h"
#include "junkie/proto/eth.h"
#include "junkie/proto/ip.h"
#include "junkie/proto/gre.h"
#include "junkie/proto/arp.h"
#include "junkie/proto/udp.h"
#include "junkie/proto/icmp.h"
#include "junkie/proto/tcp.h"
#include "junkie/proto/sip.h"
#include "junkie/proto/bittorrent.h"
#include "junkie/proto/http.h"
#include "junkie/proto/rtp.h"
#include "junkie/proto/netbios.h"
#include "junkie/proto/ssl.h"
#include "junkie/proto/dns.h"
#include "junkie/proto/rtcp.h"
#include "junkie/proto/ftp.h"
#include "junkie/proto/mgcp.h"
#include "junkie/proto/sdp.h"
#include "junkie/proto/sql.h"

static char const Id[] = "$Id$";
static char *opt_port =  "28999";
static struct sock sock;
static uint_least32_t nb_rcvd_msgs, nb_lost_msgs;

static int dump_proto_stack(struct proto_info *info)
{
    if (info->parent) (void)dump_proto_stack(info->parent);
    printf("%s: %s\n", info->parser->proto->name, info->parser->proto->ops->info_2_str(info));
    return 0;
}

/*
 * Initialize all components
 */

static struct {
    void (*init)(void);
    void (*fini)(void);
} initers[] = {
#   define I(x) { x##_init, x##_fini }
    I(log),           I(ext),         I(redim_array),
    I(mallocer),      I(mutex),
    I(hash),
    I(pkt_wait_list), I(port_muxer),
    I(cap),           I(eth),         I(arp),
    I(ip6),           I(ip),          I(gre),
    I(udp),           I(icmpv6),      I(tcp),
    I(icmp),          I(sip),         I(bittorrent),
    I(http),          I(rtp),         I(netbios),
    I(ssl),           I(dns),         I(rtcp),
    I(dns_tcp),       I(ftp),         I(mgcp),
    I(sdp),           I(postgres),    I(mysql),
    I(tns),
    I(cli),      I(sock)
#   undef I
};

static void all_init(void)
{
    for (unsigned i = 0; i < NB_ELEMS(initers); i++) {
        initers[i].init();
    }

    ext_rebind();
}

static void all_fini(void)
{
    for (unsigned i = NB_ELEMS(initers); i > 0; ) {
        initers[--i].fini();
    }
}

/*
 * Main
 */

static int opt_version(char const unused_ *opt)
{
    printf("Nark "STRIZE(TAGNAME) " / " STRIZE(BRANCHNAME) ", compiled on " STRIZE(COMP_HOST) " @ %s\n\n", __DATE__);
    exit(EXIT_SUCCESS);
}

static void loop(void)
{
    static uint8_t buf[DATAGRAM_MAX_SIZE];

    while (sock_is_opened(&sock)) {
        ssize_t s = sock_recv(&sock, buf, sizeof(buf));
        uint8_t const *ptr = buf;
        if (s > 0) {
            while (ptr < buf+s) {
                switch (*ptr++) {
                    case MSG_PROTO_INFO:
                        (void)deserialize_proto_stack(&ptr, dump_proto_stack);
                        puts("");
                        nb_rcvd_msgs ++;
                        break;
                    case MSG_PROTO_STATS:;
                        uint_least32_t nb_sent_msgs = deserialize_4(&ptr);
                        nb_lost_msgs = nb_sent_msgs-nb_rcvd_msgs;   // 2-complement rules!
                        static uint_least32_t prev_lost = 0;
                        if (nb_lost_msgs != prev_lost) {
                            prev_lost = nb_lost_msgs;
                            fprintf(stderr, "lost %"PRIuLEAST32" msgs\n", nb_lost_msgs);
                        }
                        break;
                    default:
                        SLOG(LOG_ERR, "Unknown message of type %"PRIu8, ptr[-1]);
                        break;
                }
            }
        } else {
            sock_dtor(&sock);
        }
    }
}

int main(int nb_args, char **args)
{
    all_init();
    atexit(all_fini);

    static struct cli_opt main_opts[] = {
        { { "version", "v" }, false, "display version",      CLI_CALL,    { .call = opt_version } },
        { { "port", "p" },    true,  "listen on given port", CLI_DUP_STR, { .str  = &opt_port } },
    };

    cli_register(NULL, main_opts, NB_ELEMS(main_opts));

    if (0 != cli_parse(nb_args-1, args+1)) return EXIT_FAILURE;

    if (0 != sock_ctor_server(&sock, opt_port)) return EXIT_FAILURE;

    loop();

    return EXIT_SUCCESS;
}
