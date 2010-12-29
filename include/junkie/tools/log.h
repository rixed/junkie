// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef LOG_H
#define LOG_H
#include <assert.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdbool.h>
#include <junkie/cpp.h>
#include <junkie/tools/tempstr.h>
#include <junkie/tools/queue.h>

/** @file
 * @brief log facility
 */

extern bool in_background;  ///< Tells if junkie runs in daemon mode

/** Set/Change the file where the logs are written to.
 * @param filename if not NULL, the logs will be written in this file from now on. If NULL, no more logs will be outputed.
 * @note previous log file will be closed first, so that log_set_file(log_get_file()) reopens the log file.
 * @note filename is copied so you can safely dispose of it after the call.
 */
int log_set_file(char const *filename);

/// @returns the current logfile name.
char const *log_get_file(void);

#define LOG_CAT global_log_category

#define SLOG(prio, fmt, ...) do { \
    if (LOG_CAT.level >= (prio)) slog(prio, __FILE__, __func__, fmt, ##__VA_ARGS__); \
} while(/*CONSTCOND*/0)

void slog(int priority, char const *filename, char const *funcname, char* fmt, ...) a_la_printf_(4, 5);

#define SLOG_HEX(prio, buf, size) do { \
    if (LOG_CAT.level >= prio) slog_hex(prio, __FILE__, __func__, buf, size); \
} while (/*CONSTCOND*/0)
void slog_hex(int priority, char *buf, char const *filename, char const *funcname, size_t size);

#define DIE(fmt, ...) do { \
        slog(LOG_EMERG, NULL, NULL, fmt, ##__VA_ARGS__); \
        exit(EXIT_FAILURE); \
    } while (/*CONSTCOND*/0)

#define FAIL(fmt, ...) do {                               \
        char *str = tempstr_printf(fmt, ##__VA_ARGS__);   \
        assert(!str);                                     \
} while (/*CONSTCOND*/0)

/*
 * Log categories
 */

struct log_category {
    SLIST_ENTRY(log_category) entry;
    char const *name;
    int level;
};

extern SLIST_HEAD(log_categories, log_category) log_categories;

#define LOG_CATEGORY_DEC(cat_name) \
struct log_category cat_name##_log_category; \

#define LOG_CATEGORY_DEF(cat_name) \
struct log_category cat_name##_log_category = { .name = #cat_name, .level = LOG_WARNING }; \
static void log_category_##cat_name##_init(void) \
{ \
    SLIST_INSERT_HEAD(&log_categories, &cat_name##_log_category, entry); \
} \
static void log_category_##cat_name##_fini(void) \
{ \
    SLIST_REMOVE(&log_categories, &cat_name##_log_category, log_category, entry); \
}

// We have a "global" log category, used by default by SLOG if LOG_CAT is not redefined
LOG_CATEGORY_DEC(global)

/** Set log_level of some category.
 * @param level the new log level
 * @param cat_name the name of the category to change. If NULL, will change log level of all categories.
 * @note cat_name is case insensitive.
 */
void log_set_level(int level, char const *cat_name);

/** Get a log level
 * @returns -1 if the category does not exists.
 */
int log_get_level(char const *cat_name);

void log_init(void);
void log_fini(void);

#endif
