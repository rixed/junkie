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
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include "junkie/config.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "junkie/tools/log.h"
#include "junkie/tools/ext.h"
#include "junkie/tools/cli.h"
#include "junkie/tools/files.h"
#include "junkie/tools/ref.h"
#include "junkie/tools/mallocer.h"
#include "junkie/tools/hash.h"
#include "junkie/tools/redim_array.h"
#include "junkie/tools/objalloc.h"
#include "junkie/tools/timebound.h"
#include "junkie/cpp.h"
// For initers/finiters
#include "junkie/proto/streambuf.h"
#include "junkie/proto/capfile.h"
#include "junkie/proto/proto.h"
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
#include "junkie/proto/http.h"
#include "junkie/proto/rtp.h"
#include "junkie/proto/netbios.h"
#include "junkie/proto/dns.h"
#include "junkie/proto/rtcp.h"
#include "junkie/proto/ftp.h"
#include "junkie/proto/mgcp.h"
#include "junkie/proto/sdp.h"
#include "junkie/proto/sql.h"
#include "junkie/proto/tls.h"
#include "junkie/proto/erspan.h"
#include "junkie/proto/fcoe.h"
#include "junkie/proto/skinny.h"
#include "junkie/proto/dhcp.h"
#include "junkie/proto/port_muxer.h"
#include "junkie/proto/cnxtrack.h"
#include "junkie/proto/serialize.h"
#include "junkie/proto/os-detect.h"
#include "junkie/proto/discovery.h"
#include "junkie/proto/cifs.h"
#include "proto/fuzzing.h"
#include "pkt_source.h"
#include "plugins.h"
#include "nettrack.h"

/*
 * Initialize all components
 */

static struct {
    void (*init)(void);
    void (*fini)(void);
} initers[] = {
#   define I(x) { x##_init, x##_fini }
    I(objalloc),      I(plugins),     I(nettrack),
    I(cnxtrack),      I(proto),       I(fuzzing),
    I(pkt_wait_list), I(port_muxer),  I(streambuf),
    I(timebound),
    I(cap),           I(eth),         I(arp),
    I(ip),            I(ip6),         I(gre),
    I(udp),           I(icmpv6),      I(tcp),
    I(icmp),          I(sip),
    I(http),          I(rtp),         I(netbios),
    I(dns),           I(rtcp),        I(cifs),
    I(dns_tcp),       I(ftp),         I(mgcp),
    I(sdp),           I(pgsql),       I(mysql),
    I(tns),           I(tls),         I(erspan),
    I(skinny),        I(dhcp),        I(fcoe),
    I(discovery),
    I(pkt_source),    I(capfile),     I(serialize)
#   undef I
};

static void all_init(void)
{
    log_init();
    files_init();
    ext_init();
    cli_init();
    mallocer_init();    // as all users do not init it...
    ref_init(); // as all users do not init it...
    hash_init();    // as all users do not init it...
    redim_array_init(); // if there are no users then some ext functions used by the www interface won't be defined
    os_detect_init();   // dummy function just to include os_detect in junkie (that does not use it, but plugins may want to)

    // Openssl don't like to be inited several times so let's do it once and for all
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    for (unsigned i = 0; i < NB_ELEMS(initers); i++) {
        initers[i].init();
    }

    ext_rebind();
}

static void all_fini(void)
{
    // Make some effort to honnor any plugins destructor at exit

    doomer_stop();  // doomer_thread must not awake while we destroy parsers, plugins, and so on

    plugin_del_all();

    for (unsigned i = NB_ELEMS(initers); i > 0; ) {
        initers[--i].fini();
    }

#   ifdef DELETE_ALL_AT_EXIT
    /* This is sometime usefull to clean all allocated ressources
     * at exit to help valgrind help us find memory leaks. */
    ERR_free_strings();
#   endif

    redim_array_fini();
    hash_fini();
    ref_fini();
    mallocer_fini();
    cli_fini();
    ext_fini();
    files_fini();
    log_fini();
}

/*
 * Main program loop
 */

static void loop(sigset_t *set)
{
    for (;;) {
        int sig;
        if (0 != sigwait(set, &sig)) continue;

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

    // First we want to block all signals we will read later using sigwait, before some threads are spawned.
    sigset_t set;
    sigemptyset(&set);
    // Reopen log file (used by logrotate).
    sigaddset(&set, SIGHUP);
    // On a ^C, or a kill, we want to call exit() so that all destructors are run
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    // Can receive it occasionally
    sigaddset(&set, SIGPIPE);
    sigaddset(&set, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    all_init();
    atexit(all_fini);

    // Default command line arguments
    static struct cli_opt main_opts[] = {
        { { "version", "v" }, NULL,      "display version",               CLI_CALL,     { .call = opt_version } },
        { { "config", "c" },  "file",    "load configuration (will prevent default config file to be loaded)",
                                                                          CLI_CALL,     { .call = opt_config } },
        { { "syslog", NULL }, NULL,      "use syslog for critical msgs",  CLI_SET_BOOL, { .boolean = &use_syslog } },
        { { "exec", "e" },    "s-expr",  "execute given command",         CLI_CALL,     { .call = ext_eval } },
        { { "log", "l" },     "file",    "log into this file",            CLI_CALL,     { .call = opt_logfile } },
        { { "load", "p" },    "file.so", "load this plugin",              CLI_CALL,     { .call = opt_plugin } },
        { { "iface", "i" },   "iface",   "listen this interface",         CLI_CALL,     { .call = opt_iface } },
        { { "filter", "f" },  "filter",  "open next ifaces with this BPF filter",
                                                                          CLI_DUP_STR,  { .str = &default_bpf_filter } },
        { { "read", "r" },    "file",    "read this pcap file",           CLI_CALL,     { .call = opt_read } },
        { { "count", NULL },  "nb-pkts", "Exit after displaying this amount of packets",
                                                                          CLI_SET_UINT, { .uint = &pkt_count } },
    };

    cli_register(NULL, main_opts, NB_ELEMS(main_opts));

    if (0 != cli_parse(nb_args-1, args+1)) return EXIT_FAILURE;

    set_thread_name("J-main");
    openlog("junkie", LOG_CONS | LOG_NOWAIT | LOG_PID, LOG_USER);

    // The log file is easier to read if distinct sessions are clearly separated :
    SLOG(LOG_INFO, "-----  Junkie Starting  -----");

    if (! some_conffile_loaded) {
        load_if_exist(STRIZE(SYSCONFDIR) "/junkie.scm");
    }

    loop(&set);

    // never reached
    return EXIT_SUCCESS;
}

