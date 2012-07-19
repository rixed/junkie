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
#include <string.h>
#include <sys/types.h>
#include <regex.h>
#include "junkie/cpp.h"
#include "junkie/tools/cli.h"
#include "junkie/tools/ext.h"
#include "junkie/tools/queue.h"
#include "junkie/tools/mutex.h"
#include "junkie/tools/objalloc.h"
#include "junkie/proto/capfile.h"
#include "junkie/proto/proto.h"
#include "junkie/proto/cap.h"
#include "junkie/netmatch.h"

#undef LOG_CAT
#define LOG_CAT writer_log_category

LOG_CATEGORY_DEF(writer);


/*
 * A capture is governed by a capture_conf object that describes this capture policy.
 * This object is in turn available to guile.
 */

struct capture_conf {
    char *file;
    LIST_ENTRY(capture_conf) entry;
    bool listed;    // if in conf_captures list
    bool paused;
    enum file_type { PCAP, CSV } method;
    unsigned max_pkts;
    unsigned max_size;
    unsigned max_secs;
    unsigned cap_len;
    unsigned rotation;
    bool re_set, netmatch_set;
    regex_t match_re;
    struct netmatch_filter netmatch;
    struct capfile *capfile;
};

static LIST_HEAD(capture_confs, capture_conf) capture_confs;    // list of all activated capture_confs
static struct mutex confs_lock; // protects the above list

// This really must be a projection since we might destruct from unload independantly from guile's GC
static void capture_conf_dtor(struct capture_conf *conf)
{
    SLOG(LOG_DEBUG, "Destructing capture_conf %s@%p", conf->file, conf);

    if (conf->listed) {
        mutex_lock(&confs_lock);
        LIST_REMOVE(conf, entry);
        conf->listed = false;
        mutex_unlock(&confs_lock);
    }

    if (conf->re_set) {
        regfree(&conf->match_re);
        conf->re_set = false;
    }

    if (conf->netmatch_set) {
        netmatch_filter_dtor(&conf->netmatch);
        conf->netmatch_set = false;
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
    assert(! conf->re_set);

    int err = regcomp(&conf->match_re, value, REG_NOSUB|REG_ICASE);
    if (err) {
        char errbuf[1024];
        regfree(&conf->match_re);
        regerror(err, &conf->match_re, errbuf, sizeof(errbuf));
        SLOG(LOG_ERR, "Cannot compile regular expression '%s': %s", value, errbuf);
        return -1;
    }

    conf->re_set = true;
    return 0;
}

static int set_netmatch(struct capture_conf *conf, char const *value)
{
    assert(! conf->netmatch_set);

    scm_dynwind_begin(0);
    int err = -1;

    /* value is an expression that we are supposed to compile with (@ (junkie netmatch netmatch) compile) as
     * a matching function named "match" */
    char *cmd = tempstr_printf("((@ (junkie netmatch netmatch) compile) '((\"match\" . %s)) '() \"\")", value);
    SLOG(LOG_DEBUG, "Evaluating scheme string '%s'", cmd);
    SCM pair = scm_c_eval_string(cmd);

    if (scm_is_pair(pair)) {
        char *libname = scm_to_locale_string(SCM_CAR(pair));
        scm_dynwind_free(libname);
        unsigned nb_regs = scm_to_uint(SCM_CDR(pair));

        if (0 == netmatch_filter_ctor(&conf->netmatch, libname, nb_regs)) {
            conf->netmatch_set = true;
            err = 0;
        }
    }

    scm_dynwind_end();
    return err;
}

static void conf_capture_start(struct capture_conf *conf)
{
    if (! conf->file) return;
    if (conf->capfile) {
        SLOG(LOG_ERR, "Capture into %s is already started", conf->file);
        return;
    }
    SLOG(LOG_DEBUG, "Starting capture %s", conf->file);

    switch (conf->method) {
        case PCAP:
            conf->capfile = capfile_new_pcap(conf->file, conf->max_pkts, conf->max_size, conf->max_secs, conf->cap_len, conf->rotation);
            break;
        case CSV:
            conf->capfile = capfile_new_csv(conf->file, conf->max_pkts, conf->max_size, conf->max_secs, conf->cap_len, conf->rotation);
            break;
    }
}

static void conf_capture_stop(struct capture_conf *conf)
{
    if (! conf->file) return;
    if (! conf->capfile) {
        SLOG(LOG_ERR, "Capture into %s is not started", conf->file);
        return;
    }
    SLOG(LOG_DEBUG, "Stoping capture %s", conf->file);

    conf->capfile->ops->del(conf->capfile);
    conf->capfile = NULL;
}

/*
 * Command line has a special capture_conf (unavailable from guile)
 */

static struct capture_conf cli_conf = { .listed = false, .paused = false, .method = PCAP, .re_set = false, .netmatch_set = false };

// Called by the CLI parser to set cli_conf.match_re
static int cli_match_re(char const *value)
{
    return set_match_re(&cli_conf, value);
}

// Called by the CLI parser to set cli_conf.netmatch
static int cli_netmatch(char const *value)
{
    return set_netmatch(&cli_conf, value);
}

/*
 * Per packet Callback
 */

static bool info_match(struct capture_conf const *conf, struct proto_info const *info, size_t cap_len, uint8_t const *packet)
{
    if (conf->re_set) {
        char const *repr = capfile_csv_from_info(info);
        SLOG(LOG_DEBUG, "Representation: %s", repr);
        if (0 != regexec(&conf->match_re, repr, 0, NULL, 0)) return false;
    }

    if (conf->netmatch_set) {
        struct npc_register rest = { .size = cap_len, .value = (uintptr_t)packet };
        // FIXME: here we pass NULL as the new regfile since we are not supposed to bind anything. Ensure this using match purity property.
        if (! conf->netmatch.match_fun(info, rest, NULL, NULL)) return false;
    }

    return true;
}

static void try_write(struct capture_conf *conf, struct proto_info const *info, size_t cap_len, uint8_t const *packet)
{
    if (conf->capfile && !conf->paused && info_match(conf, info, cap_len, packet)) {
        //SLOG(LOG_DEBUG, "Saving a packet into %s", conf->file);
        (void)conf->capfile->ops->write(conf->capfile, info, cap_len, packet);
    }
}

static void pkt_callback(struct proto_subscriber unused_ *s, struct proto_info const *info, size_t cap_len, uint8_t const *packet, struct timeval const unused_ *now)
{
    static bool cli_inited = false;
    if (! cli_inited) {
        conf_capture_start(&cli_conf);
        cli_inited = true;
    }

    try_write(&cli_conf, info, cap_len, packet);

    mutex_lock(&confs_lock);
    struct capture_conf *conf;
    LIST_FOREACH(conf, &capture_confs, entry) {
        assert(conf->listed);
        try_write(conf, info, cap_len, packet);
    }
    mutex_unlock(&confs_lock);
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
    scm_puts(conf->method == PCAP ? " method=PCAP":" method=CSV", port);
    if (! conf->capfile) scm_puts(" NotStarted", port);
    if (conf->paused) scm_puts(" Paused", port);
    scm_puts(">", port);

    scm_remember_upto_here_1(conf_smob);

    /* non-zero means success */
    return 1;
}

static struct ext_function sg_make_capture_conf;
static SCM g_make_capture_conf(SCM file_, SCM method_, SCM match_re_, SCM netmatch_, SCM max_pkts_, SCM max_size_, SCM max_secs_, SCM caplen_, SCM rotation_)
{
    scm_dynwind_begin(0);
    char *file = scm_to_locale_string(file_);
    scm_dynwind_unwind_handler(free, file, 0); // do not free if we exit normaly

    if (! (SCM_UNBNDP(method_) || scm_is_symbol(method_))) {
        scm_throw(scm_from_latin1_symbol("wrong-type-arg"), scm_list_1(method_));
        assert(!"Not reached");
    }

    int method = SCM_UNBNDP(method_) ? 0 : cli_2_enum(false, scm_to_latin1_string(scm_symbol_to_string(method_)), "pcap", "csv", NULL);
    if (method < 0) {
        scm_throw(scm_from_latin1_symbol("no-such-method"), scm_list_1(method_));
        assert(!"Not reached");
    }

    SLOG(LOG_DEBUG, "Constructing a capture conf for file %s and method %s", file, method==PCAP ? "pcap":"csv");
    struct capture_conf *conf = scm_gc_malloc(sizeof(*conf), "capture-conf");
    conf->listed = false;
    conf->paused = false;
    conf->file = file;
    conf->method = method;
    conf->max_pkts = SCM_UNBNDP(max_pkts_) ? 0 : scm_to_uint(max_pkts_);
    conf->max_size = SCM_UNBNDP(max_size_) ? 0 : scm_to_uint(max_size_);
    conf->max_secs = SCM_UNBNDP(max_secs_) ? 0 : scm_to_uint(max_secs_);
    conf->cap_len  = SCM_UNBNDP(caplen_)   ? 0 : scm_to_uint(caplen_);
    conf->rotation = SCM_UNBNDP(rotation_) ? 0 : scm_to_uint(rotation_);
    conf->re_set = conf->netmatch_set = false;
    conf->capfile = NULL;

    SCM smob;
    SCM_NEWSMOB(smob, conf_tag, conf);

    if (SCM_BNDP(match_re_)) {
        char *match = scm_to_locale_string(match_re_);
        if (0 != set_match_re(conf, match)) {
            scm_throw(scm_from_latin1_symbol("cannot-use-regex"), scm_list_1(match_re_));
            assert(!"Not reached");
        }
    }

    if (SCM_BNDP(netmatch_)) {
        char *netmatch = scm_to_locale_string(netmatch_);
        if (0 != set_netmatch(conf, netmatch)) {
            scm_throw(scm_from_latin1_symbol("cannot-use-netmatch"), scm_list_1(netmatch_));
            assert(!"Not reached");
        }
    }

    mutex_lock(&confs_lock);
    LIST_INSERT_HEAD(&capture_confs, conf, entry);
    conf->listed = true;
    mutex_unlock(&confs_lock);

    scm_dynwind_end();

    return smob;
}

static struct ext_function sg_capture_start;
static SCM g_capture_start(SCM conf_smob)
{
    scm_assert_smob_type(conf_tag, conf_smob);
    struct capture_conf *conf = (struct capture_conf *)SCM_SMOB_DATA(conf_smob);
    conf_capture_start(conf);

    scm_remember_upto_here_1(conf_smob);

    return SCM_UNSPECIFIED;
}

static struct ext_function sg_capture_stop;
static SCM g_capture_stop(SCM conf_smob)
{
    scm_assert_smob_type(conf_tag, conf_smob);
    struct capture_conf *conf = (struct capture_conf *)SCM_SMOB_DATA(conf_smob);
    conf_capture_stop(conf);

    scm_remember_upto_here_1(conf_smob);

    return SCM_UNSPECIFIED;
}

static struct ext_function sg_capture_pause;
static SCM g_capture_pause(SCM conf_smob)
{
    scm_assert_smob_type(conf_tag, conf_smob);
    struct capture_conf *conf = (struct capture_conf *)SCM_SMOB_DATA(conf_smob);
    conf->paused = true;
    scm_remember_upto_here_1(conf_smob);
    return SCM_UNSPECIFIED;
}

static struct ext_function sg_capture_resume;
static SCM g_capture_resume(SCM conf_smob)
{
    scm_assert_smob_type(conf_tag, conf_smob);
    struct capture_conf *conf = (struct capture_conf *)SCM_SMOB_DATA(conf_smob);
    conf->paused = false;
    scm_remember_upto_here_1(conf_smob);
    return SCM_UNSPECIFIED;
}

static SCM unset_sym;
static SCM pcap_sym;
static SCM csv_sym;
static SCM paused_sym;
static SCM filetype_sym;
static SCM max_pkts_sym;
static SCM max_size_sym;
static SCM max_secs_sym;
static SCM cap_len_sym;
static SCM rotation_sym;
static SCM nb_pkts_sym;
static SCM fsize_sym;
static SCM fnum_sym;

static struct ext_function sg_capture_stats;
static SCM g_capture_stats(SCM conf_smob)
{
    scm_assert_smob_type(conf_tag, conf_smob);
    struct capture_conf *conf = (struct capture_conf *)SCM_SMOB_DATA(conf_smob);
    return scm_list_n(
            scm_cons(paused_sym,   scm_from_bool(conf->paused)),
            scm_cons(filetype_sym, conf->method == PCAP ? pcap_sym : csv_sym),
            scm_cons(max_pkts_sym, conf->max_pkts ? scm_from_uint(conf->max_pkts) : unset_sym),
            scm_cons(max_size_sym, conf->max_size ? scm_from_uint(conf->max_size) : unset_sym),
            scm_cons(max_secs_sym, conf->max_secs ? scm_from_uint(conf->max_secs) : unset_sym),
            scm_cons(cap_len_sym,  conf->cap_len  ? scm_from_uint(conf->cap_len)  : unset_sym),
            scm_cons(rotation_sym, conf->rotation ? scm_from_uint(conf->rotation) : unset_sym),
            scm_cons(nb_pkts_sym,  conf->capfile ? scm_from_uint(conf->capfile->nb_pkts) : unset_sym),
            scm_cons(fsize_sym,    conf->capfile ? scm_from_size_t(conf->capfile->file_size) : unset_sym),
            scm_cons(fnum_sym,     conf->capfile ? scm_from_uint(conf->capfile->file_num) : unset_sym),
            SCM_UNDEFINED);

    scm_remember_upto_here_1(conf_smob);
}

/*
 * Init
 */

// Extension of the command line:
static struct cli_opt writer_opts[] = {
    { { "file", NULL },     "file",    "name of the capture file",                 CLI_DUP_STR,  { .str = &cli_conf.file } },
    { { "method", NULL },   NEEDS_ARG, "pcap|csv",                                 CLI_SET_ENUM, { .uint = &cli_conf.method } },
    { { "match-re", NULL }, "regex",   "save only packets matching this "
                                       "regular expression",                       CLI_CALL,     { .call = &cli_match_re } },
    { { "netmatch", NULL }, "s-expr",  "save only packets matching this "
                                       "netmatch expression",                      CLI_CALL,     { .call = &cli_netmatch } },
    { { "max-pkts", NULL }, NEEDS_ARG, "max number of packets to capture",         CLI_SET_UINT, { .uint = &cli_conf.max_pkts } },
    { { "max-size", NULL }, NEEDS_ARG, "max size of the file",                     CLI_SET_UINT, { .uint = &cli_conf.max_size } },
    { { "max-secs", NULL }, NEEDS_ARG, "max lifespan of the file (in secs)",       CLI_SET_UINT, { .uint = &cli_conf.max_secs } },
    { { "caplen", NULL },   NEEDS_ARG, "max capture size of each packets",         CLI_SET_UINT, { .uint = &cli_conf.cap_len } },
    { { "rotation", NULL }, NEEDS_ARG, "when a file is done, opens another one, "
                                       "up to this number after which rotates. "
                                       "will create files suffixed with numbers.", CLI_SET_UINT, { .uint = &cli_conf.rotation } },
};

static struct proto_subscriber subscription;

void on_load(void)
{
    log_category_writer_init();
    objalloc_init();
    SLOG(LOG_INFO, "Loading writer");
    cli_register("Writer plugin", writer_opts, NB_ELEMS(writer_opts));
    LIST_INIT(&capture_confs);
    mutex_ctor(&confs_lock, "capture_confs");

	unset_sym    = scm_permanent_object(scm_from_latin1_symbol("unset"));
	pcap_sym     = scm_permanent_object(scm_from_latin1_symbol("PCAP"));
	csv_sym      = scm_permanent_object(scm_from_latin1_symbol("CSV"));
	paused_sym   = scm_permanent_object(scm_from_latin1_symbol("paused"));
	filetype_sym = scm_permanent_object(scm_from_latin1_symbol("file-type"));
	max_pkts_sym = scm_permanent_object(scm_from_latin1_symbol("max-pkts"));
	max_size_sym = scm_permanent_object(scm_from_latin1_symbol("max-size"));
	max_secs_sym = scm_permanent_object(scm_from_latin1_symbol("max-secs"));
	cap_len_sym  = scm_permanent_object(scm_from_latin1_symbol("cap-size"));
	rotation_sym = scm_permanent_object(scm_from_latin1_symbol("rotation"));
	nb_pkts_sym  = scm_permanent_object(scm_from_latin1_symbol("nb-pkts"));
	fsize_sym    = scm_permanent_object(scm_from_latin1_symbol("file-size"));
	fnum_sym     = scm_permanent_object(scm_from_latin1_symbol("file-num"));

    // Init SMOB type
    conf_tag = scm_make_smob_type("capture-conf", sizeof (struct capture_conf));
    scm_set_smob_free(conf_tag, free_conf);
    scm_set_smob_print(conf_tag, print_conf);
    ext_function_ctor(&sg_make_capture_conf,
        "make-capture-conf", 1, 8, 0, g_make_capture_conf,
        "(make-capture-conf \"some/file\"\n"
        "                   'csv ; method, either 'csv or 'pcap\n"
        "                   \"some regex\" ; optional, regular expression\n"
        "                   \"some netmatch filter\" : optional, netmatch filter\n"
        "                   max-pkts max-size max-secs caplen rotation) ; optional as well\n"
        "                   : create a capture configuration (but does not start it).\n"
        "See also (? 'capture-start) for actually starting the capture.\n");

    ext_function_ctor(&sg_capture_start,
        "capture-start", 1, 0, 0, g_capture_start,
        "(capture-start capture): start the capture.\n"
        "Starting a capture will overwrite the previously captured files.\n"
        "See also (? 'capture-stop)\n");

    ext_function_ctor(&sg_capture_stop,
        "capture-stop", 1, 0, 0, g_capture_stop,
        "(capture-stop capture): stop the capture\n"
        "See also (? 'capture-start)\n");

    ext_function_ctor(&sg_capture_pause,
        "capture-pause", 1, 0, 0, g_capture_pause,
        "(capture-pause capture): pause the capture\n"
        "See also (? 'capture-resume)\n");

    ext_function_ctor(&sg_capture_resume,
        "capture-resume", 1, 0, 0, g_capture_resume,
        "(capture-resume capture): resume the capture\n"
        "See also (? 'capture-pause)\n");

    ext_function_ctor(&sg_capture_stats,
        "capture-stats", 1, 0, 0, g_capture_stats,
        "(capture-stats capture): return some infos & stats\n");

    proto_pkt_subscriber_ctor(&subscription, pkt_callback);
}

void on_unload(void)
{
    SLOG(LOG_INFO, "Unloading writer");
    proto_pkt_subscriber_dtor(&subscription);
    cli_unregister(writer_opts);

    capture_conf_dtor(&cli_conf);
    struct capture_conf *conf;
    while (NULL != (conf = LIST_FIRST(&capture_confs))) {
        assert(conf->listed);
        capture_conf_dtor(conf);
    }

    mutex_dtor(&confs_lock);
    objalloc_fini();
    log_category_writer_fini();
}

