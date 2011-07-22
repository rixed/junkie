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
#include <libgen.h>     /* basename */
#include <sys/stat.h>       /* umask needed to fork */
#include <junkie/config.h>
#include <junkie/tools/log.h>
#include <junkie/tools/files.h>
#include <junkie/tools/mutex.h>
#include <junkie/tools/ext.h>
#include <junkie/tools/ref.h>
#include <junkie/cpp.h>
#include <junkie/capfile.h>
// For initers/finiters
#include <junkie/tools/redim_array.h>
#include <junkie/tools/mallocer.h>
#include <junkie/tools/mutex.h>
#include <junkie/tools/hash.h>
#include <junkie/tools/cli.h>
#include <junkie/proto/proto.h>
#include <junkie/proto/pkt_wait_list.h>
#include <junkie/proto/cap.h>
#include <junkie/proto/eth.h>
#include <junkie/proto/ip.h>
#include <junkie/proto/gre.h>
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
    I(log),           I(ext),         I(redim_array),
    I(mallocer),      I(mutex),       I(plugins),
    I(hash),          I(proto),       I(fuzzing),
    I(pkt_wait_list), I(ref),         I(cap),
    I(eth),           I(ip6),         I(arp),
    I(ip),            I(gre),         I(udp),
    I(icmpv6),        I(tcp),         I(icmp),
    I(sip),           I(bittorrent),  I(http),
    I(rtp),           I(netbios),     I(ssl),
    I(dns),           I(rtcp),        I(dns_tcp),
    I(ftp),           I(mgcp),        I(sdp),
    I(postgres),      I(mysql),       I(tns),
    I(pkt_source),    I(cli),         I(capfile),
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

    // Could receive it occasionally
    sigaddset(set, SIGPIPE);
    sigaddset(set, SIGCHLD);
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
                SLOG(LOG_INFO, "SIGINT Caught. Exiting.");
                exit(EXIT_SUCCESS); // call all destructors
                break;
            case SIGPIPE:
                SLOG(LOG_INFO, "SIGPIPE Caught. Ignoring.");
                break;
            case SIGCHLD:
                SLOG(LOG_INFO, "SIGCHLD Caught. Ignoring.");
                break;
        }
    }
}

/*
 * Command line handling
 */

static bool some_conffile_loaded = false;

static int opt_version(char const unused_ *opt)
{
    printf("Junkie %s\n\n", version_string);
    exit(EXIT_SUCCESS);
}

static int opt_config(char const *opt)
{
    some_conffile_loaded = true;
    return ext_eval(tempstr_printf("(load \"%s\")", opt));
}

static int opt_logfile(char const *opt)
{
    return ext_eval(tempstr_printf("(set-log-file \"%s\")", opt));
}

static int opt_plugin(char const *opt)
{
    return ext_eval(tempstr_printf("(load-plugin \"%s\")", opt));
}

static int opt_iface(char const *opt)
{
    return ext_eval(tempstr_printf("(open-iface \"%s\")", opt));
}

static int opt_read(char const *opt)
{
    return ext_eval(tempstr_printf("(open-pcap \"%s\")", opt));
}

static void load_if_exist(char const *fname)
{
    if (file_exists(fname)) {
        SLOG(LOG_INFO, "Loading default configuration file '%s'", fname);
        (void)ext_eval(tempstr_printf("(load \"%s\")", fname));
    } else {
        SLOG(LOG_INFO, "Default configuration file '%s' not present", fname);
    }
}

int main(int nb_args, char **args)
{
    // Start by building the version string that's used in usage and --version option
    snprintf(version_string, sizeof(version_string), STRIZE(TAGNAME) " / " STRIZE(BRANCHNAME) ", compiled on " STRIZE(COMP_HOST) " @ %s", __DATE__);
    all_init();
    atexit(all_fini);

    // Default command line arguments
    static struct cli_opt main_opts[] = {
        { { "version", "v" }, false, "display version",               CLI_CALL,     { .call = opt_version } },
        { { "config", "c" },  true,  "load configuration file (will prevent default config file to be loaded)",
                                                                      CLI_CALL,     { .call = opt_config } },
        { { "syslog", NULL }, false, "use syslog for critical msgs",  CLI_SET_BOOL, { .boolean = &use_syslog } },
        { { "exec", "e" },    true,  "execute given command",         CLI_CALL,     { .call = ext_eval } },
        { { "log", "l" },     true,  "log into this file",            CLI_CALL,     { .call = opt_logfile } },
        { { "load", "p" },    true,  "load this plugin",              CLI_CALL,     { .call = opt_plugin } },
        { { "iface", "i" },   true,  "listen this interface",         CLI_CALL,     { .call = opt_iface } },
        { { "read", "r" },    true,  "read this pcap file",           CLI_CALL,     { .call = opt_read } },
    };

    cli_register(NULL, main_opts, NB_ELEMS(main_opts));

    if (0 != cli_parse(nb_args-1, args+1)) return EXIT_FAILURE;

    set_thread_name("J-main");
    openlog("junkie", LOG_CONS | LOG_NOWAIT | LOG_PID, LOG_USER);

    // The log file is easier to read if distinct sessions are clearly separated :
    SLOG(LOG_INFO, "-----  Starting  -----");

    if (! some_conffile_loaded) {
        load_if_exist(STRIZE(SYSCONFDIR) "/junkie.scm");
    }

    loop();

    return EXIT_SUCCESS;
}

