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
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <getopt.h>     /* command line parsing */
#include <libgen.h>     /* basename */
#include <sys/stat.h>       /* umask needed to fork */
#include <junkie/config.h>
#include <junkie/tools/log.h>
#include <junkie/tools/files.h>
#include <junkie/tools/mutex.h>
#include <junkie/tools/ext.h>
#include <junkie/cpp.h>
// For initers/finiters
#include <junkie/tools/redim_array.h>
#include <junkie/tools/mallocer.h>
#include <junkie/tools/mutex.h>
#include <junkie/tools/hash.h>
#include <junkie/proto/proto.h>
#include <junkie/proto/cap.h>
#include <junkie/proto/eth.h>
#include <junkie/proto/ip.h>
#include <junkie/proto/arp.h>
#include <junkie/proto/udp.h>
#include <junkie/proto/icmp.h>
#include <junkie/proto/tcp.h>
#include <junkie/proto/sip.h>
#include <junkie/proto/bittorrent.h>
#include <junkie/proto/http.h>
#include <junkie/proto/rtp.h>
#include <junkie/proto/netbios.h>
#include <junkie/proto/ssl.h>
#include <junkie/proto/dns.h>
#include <junkie/proto/rtcp.h>
#include <junkie/proto/ftp.h>
#include <junkie/proto/mgcp.h>
#include <junkie/proto/sdp.h>
#include <junkie/proto/sql.h>
#include "proto/fuzzing.h"
#include "pkt_source.h"
#include "plugins.h"

static char const Id[] = "$Id: 0fd857db0dc7d9cc14d4c3bb21d3095225379cf2 $";

/*
 * Initialize all components
 */

static struct {
    void (*init)(void);
    void (*fini)(void);
} initers[] = {
#   define I(x) { x##_init, x##_fini }
    I(log),         I(ext),         I(redim_array),
    I(mallocer),    I(mutex),       I(plugins),
    I(hash),        I(proto),       I(fuzzing),
    I(cap),         I(eth),         I(ip6),
    I(arp),         I(ip),          I(udp),
    I(icmpv6),      I(tcp),         I(icmp),
    I(sip),         I(bittorrent),  I(http),
    I(rtp),         I(netbios),     I(ssl),
    I(dns),         I(rtcp),        I(dns_tcp),
    I(ftp),         I(mgcp),        I(sdp),
    I(postgres),    I(mysql),       I(tns),
    I(pkt_source),
#   undef I
};

static void all_init(void)
{
    for (unsigned i = 0; i < NB_ELEMS(initers); i++) {
        initers[i].init();
    }
}

static void all_fini(void)
{
    plugin_del_all();

    for (unsigned i = NB_ELEMS(initers); i > 0; ) {
        initers[--i].fini();
    }
}

/*
 * Main program loop
 */

static void sig_set(sigset_t *set)
{
    sigemptyset(set);
    // Reopen log file (used by logrotate).
    sigaddset(set, SIGHUP);

    // On a ^C, or a kill, we want to call exit() so that all destructors are run
    sigaddset(set, SIGINT);
    sigaddset(set, SIGTERM);
}

static void loop(void)
{
    sigset_t set;
    int sig = 0;

    sig_set(&set);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    for (;;) {
        sig_set(&set);
        sigwait(&set, &sig);

        switch (sig) {
            case SIGHUP:
                SLOG(LOG_INFO, "SIGHUP Caught. Reopen logfile.");
                log_set_file(log_get_file());
                break;
            case SIGTERM:
            case SIGINT:
                SLOG(LOG_INFO, "SIGINT Caught. Exiting");
                exit(EXIT_SUCCESS); // call all destructors
                break;
        }
    }
}

/*
 * Command line handling
 */

static void usage(char *bin)
{
    fprintf(stdout,
        "Junkie %s\n"
        "Copyright 2010 SecurActive\n"
        "Junkie may be distributed under the terms of the GNU Affero General Public Licence;\n"
        "certain other uses are permitted as well.  For details, see the file\n"
        "`COPYING', which is included in the Junkie distribution.\n"
        "There is no warranty, to the extent permitted by law.\n"
        "\n"
        "Usage: %s [OPTIONS]\n"
        "\n  OPTIONS:\n"
        "\t-V, --version\n"
        "\t\tprint version information and exits\n"
        "\t-c, --config <filename>\n"
        "\t\tLoad this configuration file\n"
        "\t-e <expr>\n"
        "\t\texecute the given scheme expression after scheme startup file is loaded\n"
        "\t-b, --background\n"
        "\t\tlaunch in background\n"
        "\t-l, --logfile\n"
        "\t\tlog into this file (shortcut for -e (set-log-file XXX))\n"
        "\t-p, --plugin\n"
        "\t\tload this plugin (shortcut for -e (load-plugin XXX))\n"
        "\t-i, --ifaces\n"
        "\t\tsniff packets from this interface (shortcut for -e (open-iface XXX))\n"
        "\t-r, --read\n"
        "\t\tread packets from this pcap file (shortcut for -e (open-pcap XXX))\n"
        "\n", version_string, basename(bin));
}

static unsigned nb_expressions = 0;
static char const *scm_expressions[32];
static void add_expression(char const *expression)
{
    if (nb_expressions > NB_ELEMS(scm_expressions)) {
        fprintf(stderr, "Too many expressions (max is %u).\n", (unsigned)NB_ELEMS(scm_expressions));
        exit(EXIT_FAILURE);
    }
    scm_expressions[nb_expressions++] = expression;
}

int main(int ac, char **av)
{
    /* Check command line arguments */

    int c;          /* option character */
    int errflg = 0;     /* error counter */
    int option_index = 0;
    char *expr;

    // First by building the version string that's used in usage and --version option
    snprintf(version_string, sizeof(version_string), STRIZE(TAGNAME) " / " STRIZE(BRANCHNAME) ", compiled on " STRIZE(COMP_HOST) " @ %s", __DATE__);

    static struct option long_options[] = {
        {"version", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {"config", required_argument, 0, 'c'},
        {"background", no_argument, 0, 'b'},
        {"execute", required_argument, 0, 'e'},
        {"logfile", required_argument, 0, 'l'},
        {"plugin", required_argument, 0, 'p'},
        {"ifaces", required_argument, 0, 'i'},
        {"read", required_argument, 0, 'r'},
        {0, 0, 0, 0}
    };

    while ((c = getopt_long(ac, av, "vhc:be:l:p:i:r:T",
                long_options, &option_index)) != -1) {
        switch (c) {

        case 0:
            break;

        case 'c':
            expr = strdup(tempstr_printf("(load \"%s\")", optarg));
            add_expression(expr);
            break;

        case 'h':
            usage(av[0]);
            exit(EXIT_SUCCESS);
            break;

        case 'b':
            in_background = true;
            break;

        case 'v':
            printf("Junkie %s\n\n", version_string);
            return EXIT_SUCCESS;

        case 'e':
            add_expression(optarg);
            break;

        case 'l':
            expr = strdup(tempstr_printf("(set-log-file \"%s\")", optarg));
            add_expression(expr);
            break;

        case 'p':
            expr = strdup(tempstr_printf("(load-plugin \"%s\")", optarg));
            add_expression(expr);
            break;

        case 'i':
            expr = strdup(tempstr_printf("(open-iface \"%s\")", optarg));
            add_expression(expr);
            break;

        case 'r':
            expr = strdup(tempstr_printf("(open-pcap \"%s\")", optarg));
            add_expression(expr);
            break;

        case ':':   /* -c without operand */
            fprintf(stderr, "Option -%c requires an operand\n", optopt);
            errflg++;
            break;

        case '?':
            errflg++;
            break;

        default:
            printf("[-] ?? getopt returned character code 0%o ?\n", c);
            break;
        }
    }

    if (errflg) {
        usage(av[0]);
        return EXIT_FAILURE;
    }

    if (0 == nb_expressions) {
        usage(av[0]);
        return EXIT_SUCCESS;
    }

    all_init();
    atexit(all_fini);

    set_thread_name("J-main");
    openlog("junkie", LOG_CONS | LOG_NOWAIT | LOG_PID, LOG_USER);

    if (in_background) {
        pid_t pid, sid;
        pid = fork();

        if (pid < 0) {
            DIE("fork() failed.");
        }

        if (pid != 0) {
            /* parent process */
            return EXIT_SUCCESS;
        } else {
            /* child process */
            umask(0);
            sid = setsid();
            if (sid < 0) {
                DIE("setsid() failed child process couldn't detach from its parent");
            }
        }
    }

    if (0 != ext_eval(nb_expressions, scm_expressions)) {
        return EXIT_FAILURE;
    }

    // The log file is easier to read if distinct sessions are clearly separated :
    SLOG(LOG_INFO, "-----  Starting  -----");

    loop();

    return EXIT_SUCCESS;
}

