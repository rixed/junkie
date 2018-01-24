// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef EXT_H_100813
#define EXT_H_100813
#include <libguile.h>
#include <stdbool.h>
#include <pthread.h>
#include <assert.h>
#include <junkie/tools/queue.h>
#include <junkie/tools/miscmacs.h>
#include <junkie/tools/log.h>

/** @file
 * @brief Using Guile to extend junkie behaviors
 *
 * Guile was introduced initially to handle the configuration of junkie.
 * It allows to split the configuration into multiple files, alleviates the
 * burden of a complex command line parsing, permits to change some
 * configuration parameters in real time and query the internal state of
 * the application while it's running (thus the start-repl.scm configuration
 * file, that starts a thread listening to connections on port 29000 and fire
 * a full fledged read-eval-print-loop on it); all this without the need to
 * implement a custom parser.
 *
 * But introducing Guile as an extension language provides more than that.
 * It allows one to implement additional services easily, as is done for
 * instance in the start-snmp.scm config file to implement an SNMP subagent
 * based on the sniffer internal states to provide interesting figures
 * about network usage.
 *
 * For all this very few code is needed.
 * We use only two data types :
 *
 * - struct ext_function, which describes an extension function (available
 *   from guile but implemented in C) with its documentation;
 * - struct ext_param, which describes a C global variable that can be
 *   set or get from guile.
 */

/*
 * Utilities and misc
 */

/** This is build from the package version, and made accessible from guile
 * via the global binding 'junkie-version' */
extern char version_string[1024];

/// Evaluates an expression.
/** These expressions come from the command line arguments, which are all
 * translated into basic scheme expressions (except for the -e command line
 * parameter which directly takes a scheme expression).
 * @return -1 on error, 0 on success. */
int ext_eval(char const *);

/// Bind all defined ext_functions and ext_parameters in the extension language.
/** Might be called several times to bind new extensions loaded dynamically.
 * @return -1 on error, 0 on success. */
int ext_rebind(void);

/// Utility to convert from guile string/symbol to a tempstr (@see tempstr.h).
char *scm_to_tempstr(SCM value);

#define SCM_BNDP(x) (! SCM_UNBNDP(x))

/*
 * Parameters
 */

/// Return the SCM value of a parameter's internal value
SCM g_get_parameter_value(SCM name_);

/// Describes a parameter (a global variable in C) that can be set and get from guile.
struct ext_param {
    SLIST_ENTRY(ext_param) entry;   ///< Entry in the list of all parameters ext_params
    void *value;                    ///< Pointer to the C variable
    char const *name;               ///< Name for guile
    char const *doc;                ///< Docstring describing this parameter
    pthread_mutex_t mutex;          ///< Lock access to this variable
    SCM (*get)(void);               ///< Getter function
    SCM (*set)(SCM);                ///< Setter function
    bool bound;                     ///< Tells whether this variable was already bound
};

/// The list of all extension parameters
extern SLIST_HEAD(ext_params, ext_param) ext_params;

/// Identity MACRO used when using type SCM in an EXT_PARAM
#define scm_to_SCM(x) x
#define scm_from_SCM(x) x

/// Wrapper around pthread_mutex_unlock to accommodate the types required by scm_dynwind_unwind_handler()
void pthread_mutex_unlock_(void *mutex);

/// Macros to define a global parameter accessible from the extension language (and from C, of course), protected with a mutex.
#define EXT_PARAM_GET(value, type) \
static struct ext_param ext_param_##value; \
static SCM g_ext_param_get_##value(void) \
{ \
    assert(&ext_param_##value.bound); \
    scm_dynwind_begin(0); \
    pthread_mutex_lock(&ext_param_##value.mutex); \
    scm_dynwind_unwind_handler(pthread_mutex_unlock_, &ext_param_##value.mutex, SCM_F_WIND_EXPLICITLY); \
    SCM ret = scm_from_##type(value); \
    scm_dynwind_end(); \
    return ret; \
}

#define EXT_PARAM_SET(value, type) \
static struct ext_param ext_param_##value; \
static SCM g_ext_param_set_##value(SCM v) \
{ \
    SLOG(LOG_DEBUG, "Setting value for "#value); \
    assert(&ext_param_##value.bound); \
    scm_dynwind_begin(0); \
    pthread_mutex_lock(&ext_param_##value.mutex); \
    scm_dynwind_unwind_handler(pthread_mutex_unlock_, &ext_param_##value.mutex, SCM_F_WIND_EXPLICITLY); \
    value = scm_to_##type(v); \
    scm_dynwind_end(); \
    return SCM_UNSPECIFIED; \
}

// Vesion suitable for malloced strings (that may be NULL)
#define EXT_PARAM_STRING_GET(value) \
static struct ext_param ext_param_##value; \
static SCM g_ext_param_get_##value(void) \
{ \
    scm_dynwind_begin(0); \
    pthread_mutex_lock(&ext_param_##value.mutex); \
    scm_dynwind_unwind_handler(pthread_mutex_unlock_, &ext_param_##value.mutex, SCM_F_WIND_EXPLICITLY); \
    SCM ret = scm_from_latin1_string(value ? value : ""); \
    scm_dynwind_end(); \
    return ret; \
}

#define EXT_PARAM_STRING_SET(value) \
static struct ext_param ext_param_##value; \
static SCM g_ext_param_set_##value(SCM v) \
{ \
    SLOG(LOG_DEBUG, "Setting value for string "#value); \
    scm_dynwind_begin(0); \
    pthread_mutex_lock(&ext_param_##value.mutex); \
    scm_dynwind_unwind_handler(pthread_mutex_unlock_, &ext_param_##value.mutex, SCM_F_WIND_EXPLICITLY); \
    if (value) { \
        free(value); \
        value = NULL; \
    } \
    value = scm_to_locale_string(v); \
    scm_dynwind_end(); \
    return SCM_UNSPECIFIED; \
}

#define EXT_PARAM_SCM_SET(value) \
static struct ext_param ext_param_##value; \
static SCM g_ext_param_set_##value(SCM v) \
{ \
    SLOG(LOG_DEBUG, "Setting value for SCM "#value); \
    scm_dynwind_begin(0); \
    pthread_mutex_lock(&ext_param_##value.mutex); \
    scm_dynwind_unwind_handler(pthread_mutex_unlock_, &ext_param_##value.mutex, SCM_F_WIND_EXPLICITLY); \
    if (value != SCM_UNDEFINED) scm_gc_unprotect_object(value); \
    scm_gc_protect_object(v); \
    value = scm_to_SCM(v); \
    scm_dynwind_end(); \
    return SCM_UNSPECIFIED; \
}

#define EXT_PARAM_STRUCT_RW(value_, name_, doc_) \
static struct ext_param ext_param_##value_ = { \
    .value = &value_, .name = name_, .doc = STRIZE(name_)" : "doc_, .mutex = PTHREAD_MUTEX_INITIALIZER, \
    .get = g_ext_param_get_##value_, .set = g_ext_param_set_##value_, .bound = false };

#define EXT_PARAM_STRUCT_RO(value_, name_, doc_) \
static struct ext_param ext_param_##value_ = { \
    .value = &value_, .name = name_, .doc = STRIZE(name_)" : "doc_, .mutex = PTHREAD_MUTEX_INITIALIZER, \
    .get = g_ext_param_get_##value_, .set = NULL, .bound = false };

#define EXT_PARAM_CTORDTOR(value) \
static void ext_param_##value##_init(void) \
{ \
    SLIST_INSERT_HEAD(&ext_params, &ext_param_##value, entry); \
} \
static void ext_param_##value##_fini(void) \
{ \
    SLIST_REMOVE(&ext_params, &ext_param_##value, ext_param, entry); \
}

/** Create an extension parameter from the C global variable "value", with name "name" from guile, of type "type", with docstring "doc".
 * Notice that "type" must be so that there exist converter for it from and to SCM values (for instance, "type" can be uint since
 * there exist scm_to_uint() and scm_from_uint() functions).
 * _RO is for a read only parameter (not settable from guile) while _RW is for read-write.
 */
#define EXT_PARAM_RO(value, name, type, doc) \
    EXT_PARAM_GET(value, type) \
    EXT_PARAM_STRUCT_RO(value, name, doc) \
    EXT_PARAM_CTORDTOR(value)

#define EXT_PARAM_RW(value, name, type, doc) \
    EXT_PARAM_SET(value, type) \
    EXT_PARAM_GET(value, type) \
    EXT_PARAM_STRUCT_RW(value, name, doc) \
    EXT_PARAM_CTORDTOR(value)

#define EXT_PARAM_STRING_RW(value, name, doc) \
    EXT_PARAM_STRING_SET(value) \
    EXT_PARAM_STRING_GET(value) \
    EXT_PARAM_STRUCT_RW(value, name, doc) \
    EXT_PARAM_CTORDTOR(value)

#define EXT_PARAM_SCM_RW(value, name, doc) \
    EXT_PARAM_SCM_SET(value) \
    EXT_PARAM_GET(value, SCM) \
    EXT_PARAM_STRUCT_RW(value, name, doc) \
    EXT_PARAM_CTORDTOR(value)

/// Macros to grab/release the lock associated with a variable parameter.
#define EXT_LOCK(value) do { \
    SLOG(LOG_DEBUG, "Taking lock for "#value); \
    pthread_mutex_lock(&ext_param_##value.mutex); \
} while (0)
#define EXT_UNLOCK(value) do { \
    SLOG(LOG_DEBUG, "Releasing lock for "#value); \
    pthread_mutex_unlock(&ext_param_##value.mutex); \
} while (0)
#define WITH_EXT_LOCK(value, code) do { \
    EXT_LOCK(value); \
    do { code; } while (0); \
    EXT_UNLOCK(value); \
} while (0)

#ifdef bool
#   undef bool
typedef _Bool bool;
#endif

/*
 * Functions
 */

/// List of all exported functions
extern SLIST_HEAD(ext_functions, ext_function) ext_functions;

/// Describes an extension function, implemented in C and callable from guile
struct ext_function {
    SLIST_ENTRY(ext_function) entry;    ///< Entry in the list of all ext_functions
    char const *name;                   ///< Name of the function for guile
    int req, opt, rest;                 ///< Number of required arguments, optional arguments, rest arguments
    SCM (*implementation)();            ///< C implementation
    char const *doc;                    ///< Docstring
    bool bound;                         ///< Set once bound to guile, so that we can initialize function in batch (once guile itself is initialized)
};

/// Construct an ext_function
void ext_function_ctor(struct ext_function *, char const *name, int req, int opt, int rest, SCM (*)(), char const *doc);

void ext_init(void);
void ext_fini(void);

#endif
