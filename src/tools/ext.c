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
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <libgen.h>
#include <pthread.h>
#include <libguile.h>
#include <strings.h>
#include <junkie/config.h>
#include <junkie/cpp.h>
#include <junkie/tools/miscmacs.h>
#include <junkie/tools/log.h>
#include <junkie/tools/ext.h>

static char const Id[] = "$Id: 95a67137f8731eff13f99892ff17970aa6f224b8 $";

char version_string[1024];

struct ext_functions ext_functions = SLIST_HEAD_INITIALIZER(ext_functions);

void ext_function_ctor(struct ext_function *ef, char const *name, int req, int opt, int rest, SCM (*impl)(), char const *doc)
{
    ef->name = name;
    ef->req = req;
    ef->opt = opt;
    ef->rest = rest;
    ef->implementation = impl;
    ef->doc = doc;
    ef->bound = false;
    SLIST_INSERT_HEAD(&ext_functions, ef, entry);
}

/*
 * Misc.
 */

// FIXME: this is a hack to discover when our scm_with_guile call suceed. This function is supposed to return #f on exception but apparently it's not the case ?
#define SUCCESS (void *)0x12345

char *scm_to_tempstr(SCM value)
{
    char *str = tempstr();
    size_t len = scm_to_locale_stringbuf(value, str, TEMPSTR_SIZE);
    str[MIN(len, TEMPSTR_SIZE-1)] = '\0';
    return str;
}

// Wrapper around pthread_mutex_unlock suitable for scm_dynwind_unwind_handler
void pthread_mutex_unlock_(void *mutex)
{
    int err = pthread_mutex_unlock((pthread_mutex_t *)mutex);
    if (err) {
        SLOG(LOG_ERR, "Cannot unlock ext param mutex@%p: %s", mutex, strerror(err));
    }
}

/*
 * Shared parameters
 */

struct ext_params ext_params = SLIST_HEAD_INITIALIZER(ext_params);

static struct ext_param *get_param(char const *name)
{
    struct ext_param *param;
    SLIST_LOOKUP(param, &ext_params, entry, 0 == strcmp(name, param->name));
    return param;
}

static struct ext_function sg_parameter_names;
SCM g_parameter_names(void)
{
    SCM ret = SCM_EOL;
    struct ext_param *param;
    SLIST_FOREACH(param, &ext_params, entry) ret = scm_cons(scm_from_locale_string(param->name), ret);
    return ret;
}

static struct ext_function sg_get_parameter_value;
SCM g_get_parameter_value(SCM name_)
{
    char *name = scm_to_tempstr(name_);
    struct ext_param *param = get_param(name);
    if (! param) return SCM_UNSPECIFIED;
    return param->get();
}

/*
 * Init
 */

static void *ext_rebind_from_guile(void unused_ *dummy)
{
    // All defined functions
    struct ext_function *ef;
    SLIST_FOREACH(ef, &ext_functions, entry) {
        if (ef->bound) continue;
        if (! ef->implementation) continue;
        SLOG(LOG_INFO, "New extension function %s", ef->name);
        scm_c_define_gsubr(ef->name, ef->req, ef->opt, ef->rest, ef->implementation);
        scm_c_export(ef->name, NULL);
        ef->bound = true;
    }

    // All setters and getters for external parameters
    struct ext_param *param;
    SLIST_FOREACH(param, &ext_params, entry) {
        if (param->bound) continue;
        SLOG(LOG_INFO, "New extension parameter %s", param->name);
        char *str = tempstr_printf("get-%s", param->name);  // FIXME: check we can pass a transient name to scm_c_define_gsubr
        scm_c_define_gsubr(str, 0, 0, 0, param->get);
        scm_c_export(str, NULL);
        if (param->set) {
            str = tempstr_printf("set-%s", param->name);
            scm_c_define_gsubr(str, 1, 0, 0, param->set);
            scm_c_export(str, NULL);
        }
        param->bound = true;
    }

    return SUCCESS;
}

static void *init_scm_extensions(void unused_ *dummy)
{
    SCM module = scm_c_resolve_module("guile-user");

    // junkie-parameters: a list of parameter names
    scm_c_module_define(module, "junkie-parameters", g_parameter_names());
    scm_c_export("junkie-parameters", NULL);

    // junkie-version: a mere string to query the current junkie version
    scm_c_module_define(module, "junkie-version", scm_from_locale_string(version_string));
    scm_c_export("junkie-version", NULL);

    // bind all ext functions and parameters
    (void)ext_rebind_from_guile(NULL);

    return SUCCESS;
}

static void *eval_string(void *str)
{
    (void)scm_c_eval_string(str);
    return SUCCESS;
}

int ext_rebind(void)
{
    if (SUCCESS != scm_with_guile(ext_rebind_from_guile, NULL)) return -1;
    return 0;
}

int ext_eval(char const *expression)
{
    if (SUCCESS != scm_with_guile(eval_string, (void *)expression)) return -1;
    return 0;
}

/*
 * Help
 */

static SCM help_page_fun(struct ext_function const *fun)
{
    // Add text from function name, arity, etc, eventually ?
    return scm_from_locale_string(fun->doc);
}

static SCM help_page_param(struct ext_param const *param)
{
    return scm_from_locale_string(param->doc);
}

static SCM all_fun_help(SCM list, struct ext_function const *fun, char const *pattern)
{
    if (! fun) return list;

    if (NULL != strstr(fun->name, pattern)) {
        return all_fun_help(scm_cons(help_page_fun(fun), list), SLIST_NEXT(fun, entry), pattern);
    }
    return all_fun_help(list, SLIST_NEXT(fun, entry), pattern);
}

static SCM all_param_help(SCM list, struct ext_param *param, char const *pattern)
{
    if (! param) return list;

    if (NULL != strstr(param->name, pattern)) {
        return all_param_help(scm_cons(help_page_param(param), list), SLIST_NEXT(param, entry), pattern);
    }
    return all_param_help(list, SLIST_NEXT(param, entry), pattern);
}

static struct ext_function sg_help;
static SCM g_help(SCM topic)
{
    // topic might be a symbol or a string, or nothing.
    if (scm_is_symbol(topic)) {  // Returns this very docstring
        return g_help(scm_symbol_to_string(topic));
    } else {    // Returns the list of all matching docstrings
        char const *pattern = scm_is_string(topic) ? scm_to_tempstr(topic) : "";
        return all_fun_help(
            all_param_help(SCM_EOL, SLIST_FIRST(&ext_params), pattern),
            SLIST_FIRST(&ext_functions),
            pattern);
    }
}

/*
 * Init
 */

void ext_init(void)
{
    if (SUCCESS != scm_with_guile(init_scm_extensions, NULL)) exit(EXIT_FAILURE);

    ext_function_ctor(&sg_parameter_names,
        "parameter-names", 0, 0, 0, g_parameter_names,
        "(parameter-names): returns the list of junkie configuration parameters.\n");

    ext_function_ctor(&sg_get_parameter_value,
        "get-parameter-value", 1, 0, 0, g_get_parameter_value,
        "(get-parameter-value \"name\"): returns the value of the parameter named \"name\".\n"
        "Note: parameters can also be accessed with (get-the_parameter_name).\n"
        "See also (? 'parameter-names).\n");

    ext_function_ctor(&sg_help,
        "?", 0, 1, 0, g_help,
        "(? 'topic): get help about that topic.\n"
        "(?): get all help pages.\n"
        "(help): the same, prettified.\n");
}

void ext_fini(void)
{
}
