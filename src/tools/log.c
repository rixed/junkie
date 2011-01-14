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
#include <stdarg.h>
#include <stdio.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <junkie/tools/miscmacs.h>
#include <junkie/tools/log.h>
#include <junkie/tools/tempstr.h>
#include <junkie/tools/files.h>
#include <junkie/tools/mutex.h>
#include <junkie/tools/ext.h>

static char const Id[] = "$Id: 52f0ab48ebbc1c5ea1bfbb807f830aeda7b80275 $";

bool in_background = false;

struct log_categories log_categories = SLIST_HEAD_INITIALIZER(&log_categories);

LOG_CATEGORY_DEF(global)

static int log_fd = -1;
static char log_filename[PATH_MAX];

static void vsystem_log(int priority, char const *fmt, va_list ap)
{
    if (in_background) {
        vsyslog(priority, fmt, ap);
    } else {
        vfprintf(stderr, fmt, ap);
        fprintf(stderr, "\n");
    }
}

static void a_la_printf_(2,3) system_log(int priority, char const *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsystem_log(priority, fmt, ap);
    va_end(ap);
}

int log_set_file(char const *filename)
{
    // First close what was opened
    if (log_fd != -1) {
        (void)close(log_fd);
        log_fd = -1;
    }

    if (! filename) return 0;

    if (0 != mkdir_all(filename, true)) {
        system_log(LOG_ERR, "Cannot create directory for log file '%s'", filename);
        return -1;
    }
    log_fd = open(filename, O_WRONLY | O_APPEND | O_CREAT, 0644);

    if (log_fd == -1) {
        system_log(LOG_ERR, "Cannot open logfile '%s'", filename);
        return -1;
    }

    if (log_filename != filename) { // we often perform set_file(get_file), but snprintf won't work if src and dest overwrite.
        snprintf(log_filename, sizeof(log_filename), "%s", filename);
    }

    slog(LOG_INFO, __FILE__, __func__, "Opening log file.");
    return 0;
}

char const *log_get_file(void)
{
    if (log_fd == -1) return NULL;
    return log_filename;
}

/* General logging facility */
void slog(int priority, char const *filename, char const *funcname, char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    if (priority <= LOG_CRIT) {
        va_list aq;
        va_copy(aq, ap);
        vsystem_log(priority, fmt, aq);
    }

    if (log_fd != -1) {
        char str[4096];

        time_t now = time(NULL);
        struct tm tm;
        localtime_r(&now, &tm);

        int len = strftime(str, sizeof(str), "%Y-%m-%d %H:%M:%S: ", &tm);
        len += snprintf(str + len, sizeof(str) - len, "%s: ", get_thread_name());
        if (filename && funcname) len += snprintf(str + len, sizeof(str) - len, "%s/%s: ", filename, funcname);
        len += vsnprintf(str + len, sizeof(str) - len, fmt, ap);
        len += snprintf(str + len, sizeof(str) - len, "\n");
        len = MIN(len, (int)sizeof(str));

        if (write(log_fd, str, len)) {} // To clean gcc stupid warn_unused_result
    }

    va_end(ap);
}

void slog_hex(int priority, char *buf, char const *filename, char const *funcname, size_t size)
{
    char *str = tempstr();

    int len = 0;
    for (unsigned o = 0; o < size && len < TEMPSTR_SIZE; o++) {
        len += snprintf(str+len, TEMPSTR_SIZE-len, "0x%02x ", buf[o]);
    }

    slog(priority, filename, funcname, "%s", str);
}

void log_set_level(int level, char const *cat_name)
{
    // look for a log category of that name
    struct log_category *cat;
    SLIST_FOREACH(cat, &log_categories, entry) {
        if (! cat_name || strcasecmp(cat_name, cat->name) == 0) {
            SLOG(LOG_INFO, "Setting log level of %s from %d to %d", cat->name, cat->level, level);
            cat->level = level;
        }
    }
}

int log_get_level(char const *cat_name)
{
    // look for a log category of that name
    struct log_category *cat;
    SLIST_FOREACH(cat, &log_categories, entry) {
        if (strcasecmp(cat_name, cat->name) == 0) {
            return cat->level;
        }
    }

    return -1;
}

/*
 * Extension functions
 */

static struct ext_function sg_set_log_level;
static SCM g_set_log_level(SCM log_level_, SCM cat_name_)
{
    char *cat_name = cat_name_ != SCM_UNDEFINED ? scm_to_tempstr(cat_name_) : NULL;
    int log_level = scm_to_int(log_level_);
    log_set_level(log_level, cat_name);
    return SCM_UNSPECIFIED;
}

static struct ext_function sg_get_log_level;
static SCM g_get_log_level(SCM cat_name_)
{
    char *cat_name = scm_to_tempstr(cat_name_);
    int const level = log_get_level(cat_name);
    return level == -1 ? SCM_UNSPECIFIED : scm_from_int(level);
}

static SCM next_log_category(SCM list, struct log_category *next)
{
    if (! next) return list;
    return next_log_category(
        scm_cons(scm_from_locale_string(next->name), list),
        SLIST_NEXT(next, entry));
}

static struct ext_function sg_log_categories;
static SCM g_log_categories(void)
{
    return next_log_category(SCM_EOL, SLIST_FIRST(&log_categories));
}

static struct ext_function sg_set_log_file;
static SCM g_set_log_file(SCM log_file_)
{
    char *log_file = log_file_ != SCM_UNDEFINED ? scm_to_tempstr(log_file_) : NULL;
    int ret = log_set_file(log_file);
    return ret == 0 ? SCM_BOOL_T : SCM_BOOL_F;
}

static struct ext_function sg_get_log_file;
static SCM g_get_log_file(void)
{
    char const *log_file = log_get_file();
    return log_file ? scm_from_locale_string(log_file) : SCM_UNSPECIFIED;
}

void log_init(void)
{
    log_category_global_init();

    ext_function_ctor(&sg_set_log_level, "set-log-level", 1, 1, 0, g_set_log_level,
        "(set-log-level n)       : sets log level globally to n.\n"
        "(set-log-level n \"cat\") : sets log level of this category to n.\n"
        "Notice that the log level n range from 0 to 7, with the corresponding variables defined :\n"
        "log-emerg (0), log-alert, log-crit, log-err, log-warn, log-notice, log-info, log-debug (7).\n"
        "To get the list of available categories, see (? 'log-categories)\n");

    ext_function_ctor(&sg_get_log_level,
        "get-log-level", 1, 0, 0, g_get_log_level,
        "(get-log-level \"cat\") : gets the current log level for this category.\n"
        "To get the list of available categories, see (? 'log-categories)\n");

    ext_function_ctor(&sg_log_categories,
        "log-categories", 0, 0, 0, g_log_categories,
        "(log-categories) : returns a list of available log categories.\n");

    ext_function_ctor(&sg_set_log_file,
        "set-log-file", 0, 1, 0, g_set_log_file,
        "(set-log-file \"filename\") : now junkie will print logs into this file.\n"
        "(set-log-file)            : now junkie will stop loging in a file.\n"
        "See also (? 'get-log-file).\n");

    ext_function_ctor(&sg_get_log_file,
        "get-log-file", 0, 0, 0, g_get_log_file,
        "(get-log-file) : returns the filename currently used by junkie to print its log, if any.\n"
        "See also (? 'set-log-file).\n");
}

void log_fini(void)
{
    log_category_global_fini();
}
