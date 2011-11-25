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
#include "junkie/cpp.h"
#include "junkie/capfile.h"
#include "junkie/tools/cli.h"
#include "junkie/tools/ext.h"
#include "junkie/tools/queue.h"
#include "junkie/tools/mutex.h"
#include "junkie/proto/proto.h"
#include "junkie/proto/cap.h"

/*
 * A capture is governed by a capture_conf object that describes this capture policy.
 * This object is in turn available to guile.
 */

struct capture_conf {
    char *file;
    LIST_ENTRY(capture_conf) entry; // once activated, will be on the list (else NULL)
    enum file_type { PCAP, CSV } method;
    unsigned max_pkts;
    unsigned max_size;
    unsigned max_secs;
    unsigned cap_len;
    unsigned rotation;
    bool match_re_set;
    regex_t match_re;
    struct capfile *capfile;
};

static LIST_HEAD(capture_confs, capture_conf) capture_confs;    // list of all activated capture_confs
static struct mutex confs_lock; // protects the above list

static void capture_conf_dtor(struct capture_conf *conf)
{
    SLOG(LOG_DEBUG, "Destructing capture_conf %s@%p", conf->file, conf);

    if (conf->entry.le_next) {
        mutex_lock(&confs_lock);
        LIST_REMOVE(conf, entry);
        conf->entry.le_next = NULL;
        mutex_unlock(&confs_lock);
    }
    if (conf->capfile) {
        conf->capfile->ops->del(conf->capfile);
        conf->capfile = NULL;
    }
    if (conf->file) {
        free(conf->file);
        conf->file = NULL;
    }
}

static int set_match_re(struct capture_conf *conf, char const *value)
{
    int err = regcomp(&conf->match_re, value, REG_NOSUB|REG_ICASE);
    if (err) {
        char errbuf[1024];
        regfree(&conf->match_re);
        regerror(err, &conf->match_re, errbuf, sizeof(errbuf));
        SLOG(LOG_ERR, "Cannot compile regular expression '%s': %s", value, errbuf);
        return -1;
    }

    conf->match_re_set = true;
    return 0;
}

static void conf_start_capture(struct capture_conf *conf)
{
    if (! conf->file) return;

    switch (conf->method) {
        case PCAP:
            conf->capfile = capfile_new_pcap(conf->file, conf->max_pkts, conf->max_size, conf->max_secs, conf->cap_len, conf->rotation);
            break;
        case CSV:
            conf->capfile = capfile_new_csv(conf->file, conf->max_pkts, conf->max_size, conf->max_secs, conf->cap_len, conf->rotation);
            break;
    }
}

/*
 * Command line has a special capture_conf (unavailable from guile)
 */

static struct capture_conf cli_conf = { .method = PCAP };

// Called by the CLI parser to set cli_conf.match_re
static int cli_match(char const *value)
{
    return set_match_re(&cli_conf, value);
}

/*
 * Per packet Callback
 */

static bool info_match(struct capture_conf const *conf, struct proto_info const *info)
{
    if (! conf->match_re_set) return true;
    char const *repr = capfile_csv_from_info(info);
    SLOG(LOG_DEBUG, "Representation: %s", repr);
    return 0 == regexec(&conf->match_re, repr, 0, NULL, 0);
}

static void try_write(struct capture_conf *conf, struct proto_info const *info, size_t cap_len, uint8_t const *packet)
{
    if (conf->capfile && info_match(conf, info)) {
        (void)conf->capfile->ops->write(conf->capfile, info, cap_len, packet);
    }
}

int parse_callback(struct proto_info const *info, size_t cap_len, uint8_t const *packet)
{
    static bool cli_inited = false;
    if (! cli_inited) {
        conf_start_capture(&cli_conf);
        cli_inited = true;
    }

    try_write(&cli_conf, info, cap_len, packet);

    mutex_lock(&confs_lock);
    struct capture_conf *conf;
    LIST_FOREACH(conf, &capture_confs, entry) {
        try_write(conf, info, cap_len, packet);
    }
    mutex_unlock(&confs_lock);

    return 0;
}

/*
 * Extensions
 */

static scm_t_bits conf_tag;

static size_t free_conf(SCM conf_smob)
{
    struct capture_conf *conf = (struct capture_conf *)SCM_SMOB_DATA(conf_smob);
    capture_conf_dtor(conf);
    scm_gc_free(conf, sizeof(conf), "capture-conf");
    return 0;
}

static int print_conf(SCM conf_smob, SCM port, scm_print_state unused_ *pstate)
{
    struct capture_conf *conf = (struct capture_conf *)SCM_SMOB_DATA(conf_smob);

    scm_puts("#<capture-conf ", port);
    scm_display(scm_from_locale_string(conf->file ? conf->file : "no file"), port);
    scm_puts(">", port);

    /* non-zero means success */
    return 1;
}

static struct ext_function sg_make_capture_conf;
static SCM g_make_capture_conf(SCM file_, SCM method_, SCM match_, SCM max_pkts_, SCM max_size_, SCM max_secs_, SCM caplen_, SCM rotation_)
{
    char *file = scm_to_locale_string(file_);

    if (! scm_is_symbol(method_)) {
        scm_throw(scm_from_latin1_symbol("wrong-type-arg"), scm_list_1(method_));
        assert(!"Not reached");
    }

    int method = SCM_UNBNDP(match_) ? 0 : cli_2_enum(false, scm_to_latin1_string(scm_symbol_to_string(method_)), "pcap", "csv", NULL);
    if (method < 0) {
        scm_throw(scm_from_latin1_symbol("no-such-method"), scm_list_1(method_));
        assert(!"Not reached");
    }

    char *match = SCM_UNBNDP(match_) ? NULL : scm_to_locale_string(match_);

    struct capture_conf *conf = scm_gc_malloc(sizeof(*conf), "capture-conf");
    conf->entry.le_next = NULL;
    conf->file = file;
    conf->method = method;
    conf->max_pkts = SCM_UNBNDP(max_pkts_) ? 0 : scm_to_uint(max_pkts_);
    conf->max_size = SCM_UNBNDP(max_size_) ? 0 : scm_to_uint(max_size_);
    conf->max_secs = SCM_UNBNDP(max_secs_) ? 0 : scm_to_uint(max_secs_);
    conf->cap_len  = SCM_UNBNDP(caplen_)   ? 0 : scm_to_uint(caplen_);
    conf->rotation = SCM_UNBNDP(rotation_) ? 0 : scm_to_uint(rotation_);
    conf->match_re_set = false;
    conf->capfile = NULL;

    SCM smob;
    SCM_NEWSMOB(smob, conf_tag, conf);
    if (match) set_match_re(conf, match);
    conf_start_capture(conf);

    return smob;
}

/*
 * Init
 */

// Extension of the command line:
static struct cli_opt writer_opts[] = {
    { { "file", NULL },     true, "name of the capture file (or stdout)",     CLI_DUP_STR,  { .str = &cli_conf.file } },
    { { "method", NULL },   true, "pcap|csv",                                 CLI_SET_ENUM, { .uint = &cli_conf.method } },
    { { "match", NULL },    true, "save only packets matching this "
                                  "regular expression",                       CLI_CALL,     { .call = &cli_match } },
    { { "max-pkts", NULL }, true, "max number of packets to capture",         CLI_SET_UINT, { .uint = &cli_conf.max_pkts } },
    { { "max-size", NULL }, true, "max size of the file",                     CLI_SET_UINT, { .uint = &cli_conf.max_size } },
    { { "max-secs", NULL }, true, "max lifespan of the file (in secs)",       CLI_SET_UINT, { .uint = &cli_conf.max_secs } },
    { { "caplen", NULL },   true, "max capture size of each packets",         CLI_SET_UINT, { .uint = &cli_conf.cap_len } },
    { { "rotation", NULL }, true, "when a file is done, opens another one, "
                                  "up to this number after which rotates. "
                                  "will create files suffixed with numbers.", CLI_SET_UINT, { .uint = &cli_conf.rotation } },
};

void on_load(void)
{
    SLOG(LOG_INFO, "Loading writer");
    cli_register("Writer plugin", writer_opts, NB_ELEMS(writer_opts));
    LIST_INIT(&capture_confs);
    mutex_ctor(&confs_lock, "capture_confs");
    
    // Init SMOB type
    conf_tag = scm_make_smob_type("capture-conf", sizeof (struct capture_conf));
    scm_set_smob_free(conf_tag, free_conf);
    scm_set_smob_print(conf_tag, print_conf);
    ext_function_ctor(&sg_make_capture_conf,
        "make-capture-conf", 1, 7, 0, g_make_capture_conf,
        "(make-capture-conf): create a capture configuration.\n");
}

void on_unload(void)
{
    SLOG(LOG_INFO, "Unloading writer");
    cli_unregister(writer_opts);
    capture_conf_dtor(&cli_conf);
    mutex_dtor(&confs_lock);
}
