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
#include <stdint.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pcap/pcap.h>
#include "junkie/tools/tempstr.h"
#include "junkie/tools/files.h"
#include "junkie/tools/mallocer.h"
#include "junkie/tools/ext.h"
#include "junkie/tools/mutex.h"
#include "junkie/proto/cap.h"
#include "junkie/proto/capfile.h"

#undef LOG_CAT
#define LOG_CAT capfile_log_category

LOG_CATEGORY_DEF(capfile);

static unsigned capture_files = 0;
static unsigned max_capture_files = 1000;
EXT_PARAM_RW(max_capture_files, "max-capture-files", uint, "The max number of files opened for captures (0 for no limit)");

/*
 * Capfile ctor/dtor
 */

static LIST_HEAD(capfiles, capfile) capfiles = LIST_HEAD_INITIALIZER(capfiles);
static struct mutex capfiles_lock;

static void dec_capture_files(void)
{
#   ifdef __GNUC__
    unsigned prev = __sync_fetch_and_sub(&capture_files, 1);
    assert(prev > 0);
#   else
    mutex_lock(&capfiles_lock);
    assert(capture_files > 0);
    capture_files --;
    mutex_unlock(&capfiles_lock);
#   endif
}

static void inc_capture_files(void)
{
#   ifdef __GNUC__
    (void)__sync_add_and_fetch(&capture_files, 1);
#   else
    mutex_lock(&capfiles_lock);
    capture_files ++;
    mutex_unlock(&capfiles_lock);
#   endif
}

static char const *capfile_path(struct capfile *capfile)
{
    if (! capfile->rotation) return capfile->path;
    return tempstr_printf("%s.%u", capfile->path, (capfile->file_num++)%capfile->rotation);
}

static int capfile_ctor(struct capfile *capfile, struct capfile_ops const *ops, char const *path, unsigned max_pkts, size_t max_size, unsigned max_secs, size_t cap_len, unsigned rotation)
{
    MALLOCER(capfile_paths);
    mutex_ctor_with_type(&capfile->lock, path, PTHREAD_MUTEX_RECURSIVE);
    capfile->ops       = ops;
    capfile->path      = STRDUP(capfile_paths, path);
    if (! capfile->path) goto err1;
    capfile->max_pkts  = max_pkts;
    capfile->max_size  = max_size;
    capfile->max_secs  = max_secs;
    capfile->cap_len   = cap_len;
    capfile->rotation  = rotation;
    capfile->file_num  = 0;
    capfile->fd        = -1;

    if (0 != capfile->ops->open(capfile, capfile_path(capfile))) goto err2;

    mutex_lock(&capfiles_lock);
    LIST_INSERT_HEAD(&capfiles, capfile, entry);
    mutex_unlock(&capfiles_lock);
    return 0;

err2:
    FREE(capfile->path);
err1:
    mutex_dtor(&capfile->lock);
    return -1;
}

static struct capfile *capfile_new(struct capfile_ops const *ops, char const *path, unsigned max_pkts, size_t max_size, unsigned max_secs, size_t cap_len, unsigned rotation)
{
    MALLOCER(capfiles);
    struct capfile *capfile = MALLOC(capfiles, sizeof(*capfile));
    if (! capfile) return NULL;

    if (0 != capfile_ctor(capfile, ops, path, max_pkts, max_size, max_secs, cap_len, rotation)) {
        FREE(capfile);
        return NULL;
    }

    return capfile;
}

static void capfile_dtor(struct capfile *capfile)
{
    mutex_lock(&capfiles_lock);
    LIST_REMOVE(capfile, entry);
    mutex_unlock(&capfiles_lock);

    if (capfile->fd >= 0) {
        file_close(capfile->fd);
        capfile->fd = -1;
        dec_capture_files();
    }

    if (capfile->path) {
        FREE(capfile->path);
        capfile->path = NULL;
    }

    mutex_dtor(&capfile->lock);
}

static void capfile_del(struct capfile *capfile)
{
    capfile_dtor(capfile);
    FREE(capfile);
}

static void capfile_close(struct capfile *capfile)
{
    mutex_lock(&capfile->lock);
    if (capfile->fd >= 0) {
        file_close(capfile->fd);
        capfile->fd = -1;
        dec_capture_files();
    }
    mutex_unlock(&capfile->lock);
}

// Caller must own the capfile->lock
static int capfile_open(struct capfile *capfile, char const *path)
{
    if (capture_files >= max_capture_files) {   // not thread safe but if the test is not precise this is not a big deal
        SLOG(LOG_INFO, "Cannot open new capture files: %u already opened", capture_files);
        return -1;
    }

    capfile->fd = file_open(path, O_WRONLY|O_TRUNC|O_CREAT);
    if (-1 == capfile->fd) return -1;
    inc_capture_files();

    capfile->file_size = 0;
    capfile->nb_pkts = 0;
    timeval_set_now(&capfile->start);

    return 0;
}

static void capfile_may_rotate(struct capfile *capfile)
{
    mutex_lock(&capfile->lock);
    if (
        (capfile->max_pkts && capfile->nb_pkts >= capfile->max_pkts) ||
        (capfile->max_size && capfile->file_size >= capfile->max_size) ||
        (capfile->max_secs && timeval_age(&capfile->start)/1000000ULL > capfile->max_secs)
    ) {
        capfile->ops->close(capfile);

        if (capfile->rotation) {    // reopens the capfile
            SLOG(LOG_DEBUG, "Rotating capfile of %u packets", capfile->nb_pkts);
            capfile->ops->open(capfile, capfile_path(capfile));
        }
    }
    mutex_unlock(&capfile->lock);
}

/*
 * PCAP files
 * Note: we do not use libpcap because it requires an activated pcap_t for cap_len, which does not suit our case
 */

static int open_pcap(struct capfile *capfile, char const *path)
{
    int ret = -1;

    mutex_lock(&capfile->lock);

    if (0 != capfile_open(capfile, path)) goto err;

    // Write the pcap header
#   define TCPDUMP_MAGIC 0xa1b2c3d4
    struct pcap_file_header hdr = {
        .magic         = TCPDUMP_MAGIC,
        .version_major = PCAP_VERSION_MAJOR,
        .version_minor = PCAP_VERSION_MINOR,
        .thiszone      = 0,
        .snaplen       = capfile->cap_len == 0 || capfile->cap_len > 65535 ? 65535 : capfile->cap_len,
        .sigfigs       = 0,
        .linktype      = DLT_EN10MB,
    };
    if (0 != file_write(capfile->fd, &hdr, sizeof(hdr))) {
        file_close(capfile->fd);
        capfile->fd = -1;
        dec_capture_files();
        goto err;
    }

    capfile->file_size += sizeof(hdr);
    ret = 0;
err:
    mutex_unlock(&capfile->lock);
    return ret;
}

static int write_pcap(struct capfile *capfile, struct proto_info const *info, size_t cap_len_, uint8_t const *pkt)
{
    if (capfile->fd < 0) return -1;

    int err = -1;
    SLOG(LOG_DEBUG, "Add a packet of size %zu into capfile %s", cap_len_, capfile->path);
    ASSIGN_INFO_CHK(cap, info, -1);

    mutex_lock(&capfile->lock);

    size_t cap_len = capfile->cap_len ? MIN(cap_len_, capfile->cap_len) : cap_len_;

    struct pcap_sf_pkthdr {
        uint32_t ts_sec, ts_usec;
        bpf_u_int32 caplen;
        bpf_u_int32 len;
    } pkthdr = {
        .ts_sec  = cap->tv.tv_sec,
        .ts_usec = cap->tv.tv_usec,
        .caplen  = cap_len,
        .len     = cap->info.payload,
    };

    if (0 != file_write(capfile->fd, &pkthdr, sizeof(pkthdr))) goto err;
    if (0 != file_write(capfile->fd, pkt, cap_len)) goto err;

    capfile->nb_pkts++;
    capfile->file_size += sizeof(pkthdr) + cap_len;

    capfile_may_rotate(capfile);

    err = 0;
err:
    mutex_unlock(&capfile->lock);
    return err;
}

struct capfile *capfile_new_pcap(char const *path, unsigned max_pkts, size_t max_size, unsigned max_secs, size_t cap_len, unsigned rotation)
{
    static struct capfile_ops const capfile_pcap_ops = {
        .open  = open_pcap,
        .close = capfile_close,
        .write = write_pcap,
        .del   = capfile_del,
    };
    return capfile_new(&capfile_pcap_ops, path, max_pkts, max_size, max_secs, cap_len, rotation);
}

/*
 * CSV files
 */

static int open_csv(struct capfile *capfile, char const *path)
{
    mutex_lock(&capfile->lock);
    int ret = capfile_open(capfile, path);
    mutex_unlock(&capfile->lock);

    return ret;
}

char *capfile_csv_from_info(struct proto_info const *info)
{
    char const *const repr = info->parser->proto->ops->info_2_str(info);
    if (info->parent) {
        return tempstr_printf("%s/%s{%s}", capfile_csv_from_info(info->parent), info->parser->proto->name, repr);
    } else {
        return tempstr_printf("%s{%s}", info->parser->proto->name, repr);
    }
}

static int write_csv(struct capfile *capfile, struct proto_info const *info, size_t cap_len_, uint8_t const unused_ *pkt)
{
    if (capfile->fd < 0) return -1;

    int err = -1;
    SLOG(LOG_DEBUG, "Add a packet of size %zu into capfile %s", cap_len_, capfile->path);
    ASSIGN_INFO_CHK(cap, info, -1);

    mutex_lock(&capfile->lock);

    char *str = capfile_csv_from_info(info);
    size_t len = strlen(str);
    if (len >= TEMPSTR_SIZE -1) len = TEMPSTR_SIZE -1;
    str[len++] = '\n';
    str[len] = '\0';

    if (0 != file_write(capfile->fd, str, len)) goto err;

    capfile->nb_pkts++;
    capfile->file_size += len;

    capfile_may_rotate(capfile);

    err = 0;
err:
    mutex_unlock(&capfile->lock);
    return err;
}

struct capfile *capfile_new_csv(char const *path, unsigned max_pkts, size_t max_size, unsigned max_secs, size_t cap_len, unsigned rotation)
{
    static struct capfile_ops const capfile_csv_ops = {
        .open  = open_csv,
        .close = capfile_close,
        .write = write_csv,
        .del   = capfile_del,
    };
    return capfile_new(&capfile_csv_ops, path, max_pkts, max_size, max_secs, cap_len, rotation);
}

/*
 * Extension functions
 */

static struct ext_function sg_capfile_names;
static SCM g_capfile_names(void)
{
    SCM ret = SCM_EOL;

    struct capfile *capfile;

    scm_dynwind_begin(0);
    mutex_lock(&capfiles_lock);
    scm_dynwind_unwind_handler(pthread_mutex_unlock_, &capfiles_lock.mutex, SCM_F_WIND_EXPLICITLY);
    LIST_FOREACH(capfile , &capfiles, entry) {
        ret = scm_cons(scm_from_locale_string(capfile->path), ret);
    }
    scm_dynwind_end();

    return ret;
}

static unsigned inited;
void capfile_init(void)
{
    if (inited++) return;
    ext_init();
    mutex_init();

    log_category_capfile_init();
    ext_param_max_capture_files_init();
    mutex_ctor(&capfiles_lock, "capfiles");

    ext_function_ctor(&sg_capfile_names,
        "capfile-names", 0, 0, 0, g_capfile_names,
        "(capfile-names): returns the list of currently opened save files.\n"
        "See also (? 'open-capfile).\n");
}

void capfile_fini(void)
{
    if (--inited) return;

    mutex_lock(&capfiles_lock);
    if (! LIST_EMPTY(&capfiles)) {
        SLOG(LOG_WARNING, "Some capture files are still opened (first is '%s')", LIST_FIRST(&capfiles)->path);
    }
    mutex_unlock(&capfiles_lock);

    mutex_dtor(&capfiles_lock);
    ext_param_max_capture_files_fini();
    log_category_capfile_fini();

    mutex_fini();
    ext_fini();
}
