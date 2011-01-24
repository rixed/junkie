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
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <regex.h>
#include <junkie/cpp.h>
#include <junkie/capfile.h>
#include <junkie/tools/cli.h>
#include <junkie/proto/proto.h>
#include <junkie/proto/cap.h>

static char *opt_file = NULL;
static char *opt_method = "pcap";
static unsigned opt_max_pkts = 0;
static unsigned opt_max_size = 0;
static unsigned opt_max_secs = 0;
static unsigned opt_cap_len  = 0;
static unsigned opt_rotation = 0;
static regex_t match_re;
static bool match_re_set = false;

static int opt_match(char const *value)
{
    int err = regcomp(&match_re, value, REG_NOSUB|REG_ICASE);
    if (err) {
        char errbuf[1024];
        regfree(&match_re);
        regerror(err, &match_re, errbuf, sizeof(errbuf));
        SLOG(LOG_ERR, "Cannot compile regular expression '%s': %s", value, errbuf);
        return -1;
    }

    match_re_set = true;
    return 0;
}

static struct capfile *capfile = NULL;

static void init_capture(void)
{
    int e = cli_2_enum(false, opt_method, "pcap", "csv", NULL);
    if (e < 0) {
        SLOG(LOG_ERR, "Unknown file method '%s'", opt_method);
        return;
    }

    switch (e) {
        case 0: // PCAP
            capfile = capfile_new_pcap(opt_file, opt_max_pkts, opt_max_size, opt_max_secs, opt_cap_len, opt_rotation);
            break;
        case 1: // CSV
            capfile = capfile_new_csv(opt_file, opt_max_pkts, opt_max_size, opt_max_secs, opt_cap_len, opt_rotation);
            break;
    }
}

static bool info_match(struct proto_info const *info)
{
    if (! match_re_set) return true;
    char const *repr = capfile_csv_from_info(info);
    SLOG(LOG_DEBUG, "Representation: %s", repr);
    return 0 == regexec(&match_re, repr, 0, NULL, 0);
}

int parse_callback(struct proto_info const *info, size_t cap_len, uint8_t const *packet)
{
    static bool inited = false;
    if (! inited) {
        init_capture();
        inited = true;
    }

    // write it ?
    if (capfile && info_match(info)) {
        ASSIGN_INFO_CHK(cap, info, 0);
        (void)capfile->ops->write(capfile, info, cap_len, packet);
    }

    return 0;
}

// Extension of the command line:
static struct cli_opt writer_opts[] = {
    { { "file", NULL },     true, "name of the capture file",           CLI_DUP_STR,  { .str = &opt_file } },
    { { "method", NULL },   true, "csv | pcap",                         CLI_DUP_STR,  { .str = &opt_method } },
    { { "match", NULL },    true, "save only packets matching this "
                                  "regular expression",                 CLI_CALL,     { .call = &opt_match } },
    { { "max-pkts", NULL }, true, "max number of packets to capture",   CLI_SET_UINT, { .uint = &opt_max_pkts } },
    { { "max-size", NULL }, true, "max size of the file",               CLI_SET_UINT, { .uint = &opt_max_size } },
    { { "max-secs", NULL }, true, "max lifespan of the file (in secs)", CLI_SET_UINT, { .uint = &opt_max_secs } },
    { { "caplen", NULL },   true, "max capture size of each packets",   CLI_SET_UINT, { .uint = &opt_cap_len } },
    { { "rotation", NULL }, true, "when a file is done, opens another one, "
                                  "up to this number after which rotates. "
                                  "will create files suffixed with numbers.", CLI_SET_UINT, { .uint = &opt_rotation } },
};

void on_load(void)
{
    SLOG(LOG_INFO, "Loading writer");
    cli_register("Writer plugin", writer_opts, NB_ELEMS(writer_opts));
}

void on_unload(void)
{
    SLOG(LOG_INFO, "Unloading writer");
    cli_unregister(writer_opts);
    if (capfile) {
        capfile->ops->del(capfile);
        capfile = NULL;
    }
}
