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
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include "junkie/cpp.h"
#include "junkie/tools/miscmacs.h"
#include "junkie/tools/queue.h"
#include "junkie/tools/mutex.h"
#include "junkie/tools/objalloc.h"
#include "junkie/tools/ext.h"   // for version_string
#include "junkie/tools/cli.h"

struct cli_bloc {
    TAILQ_ENTRY(cli_bloc) entry;
    char const *name;
    unsigned nb_cli_opts;
    struct cli_opt *opts;
};

static TAILQ_HEAD(cli_blocs, cli_bloc) cli_blocs = TAILQ_HEAD_INITIALIZER(cli_blocs);
static struct mutex cli_mutex;

int cli_register(char const *name, struct cli_opt *opts, unsigned nb_opts)
{
    SLOG(LOG_DEBUG, "Registering a new bloc of command line options for %s", name);

    struct cli_bloc *bloc = objalloc(sizeof(*bloc), "CLI blocs");
    if (! bloc) return -1;

    bloc->name = name;
    bloc->nb_cli_opts = nb_opts;
    bloc->opts = opts;
    mutex_lock(&cli_mutex);
    TAILQ_INSERT_TAIL(&cli_blocs, bloc, entry);
    mutex_unlock(&cli_mutex);
    return 0;
}

int cli_unregister(struct cli_opt *opts)
{
    int ret = -1;

    struct cli_bloc *bloc;
    mutex_lock(&cli_mutex);
    TAILQ_FOREACH(bloc, &cli_blocs, entry) {
        if (bloc->opts != opts) continue;
        SLOG(LOG_DEBUG, "Unregistering command line option bloc for %s", bloc->name);
        TAILQ_REMOVE(&cli_blocs, bloc, entry);
        objfree(bloc);
        ret = 0;
        break;
    }
    mutex_unlock(&cli_mutex);

    return ret;
}

static bool arg_match(char const *arg, char const *opt)
{
    if (!arg || !opt) return false;
    if (0 == strcmp(arg, opt)) return true;
    if (arg[0] != '-') return false;
    if (0 == strcmp(arg+1, opt)) return true;
    if (arg[1] != '-') return false;
    if (0 == strcmp(arg+2, opt)) return true;

    return false;
}

static struct cli_opt *find_opt(char const *arg)
{
    struct cli_bloc *bloc;
    TAILQ_FOREACH(bloc, &cli_blocs, entry) {
        for (unsigned o = 0; o < bloc->nb_cli_opts; o++) {
            for (unsigned c = 0; c < NB_ELEMS(bloc->opts[o].arg); c++) {
                if (arg_match(arg, bloc->opts[o].arg[c])) {
                    return bloc->opts+o;
                }
            }
        }
    }

    return NULL;
}

static int check_bool(char const *value)
{
    return cli_2_enum(false, value, "t", "f", "true", "false", NULL) > 0 ? 0:-1;
}

int cli_parse(unsigned nb_args, char **args)
{
    if (! nb_args) return 0;
    SLOG(LOG_DEBUG, "Parse option '%s'", args[0]);

    // If args[0] have the form "name=value" change it to name then value and incr nb_args
    char *eq = strchr(args[0], '=');
    if (eq) {
        *eq = '\0';
        char *new_args[nb_args+1];
        new_args[0] = args[0];
        new_args[1] = eq+1;
        memcpy(new_args+2, args+1, (nb_args-1) * sizeof(*args));
        return cli_parse(nb_args+1, new_args);
    }

    // Beware that new options may be added while we are parsing the command line
    struct cli_opt const *const opt = find_opt(args[0]);
    if (! opt) {
        fprintf(stderr, "Unkown option '%s'\n", args[0]);
        return -1;
    }
    if (opt->arg_name && nb_args < 2) {
        fprintf(stderr, "Option '%s' requires an argument\n", args[0]);
        return -1;
    }

    int err = -1;
    switch (opt->action) {
        case CLI_CALL:
            err = opt->u.call(opt->arg_name ? args[1] : NULL);
            break;
        case CLI_SET_UINT:
            assert(opt->arg_name);
            char *end;
            *opt->u.uint = strtoul(args[1], &end, 0);
            if (*end != '\0') {
                fprintf(stderr, "Cannot parse numeric option '%s'\n", args[1]);
            } else {
                err = 0;
            }
            break;
        case CLI_SET_BOOL:
            if (! opt->arg_name) { // then the presence of the flag means yes
                *opt->u.boolean = true;
                err = 0;
            } else {
                if (0 != check_bool(args[1])) {
                    fprintf(stderr, "Cannot parse boolean value '%s'\n", args[1]);
                } else {
                    *opt->u.boolean = args[1][0] == 't' || args[1][0] == 'T';
                    err = 0;
                }
            }
            break;
        case CLI_DUP_STR:
            assert(opt->arg_name);
            // We do not know if previous value was on heap or dataseg, so better forget it.
            *opt->u.str = strdup(args[1]);
            err = *opt->u.str == NULL ? -1:0;
            break;
        case CLI_SET_ENUM:
            assert(opt->arg_name);
            unsigned v = 0;
            size_t opt_len = strlen(args[1]);
            char const *c;
            for (c = opt->help; *c; c++) {
                if (*c == '|') {
                    v ++;
                } else if (
                    (c == opt->help || c[-1] == '|') &&
                    0 == strncasecmp(c, args[1], opt_len)
                ) {
                    break;
                }
            }
            if (*c == '\0') {
                fprintf(stderr, "Cannot parse enum value '%s'\n", args[1]);
            } else {
                *opt->u.uint = v;
                err = 0;
            }
            break;
    }

    if (err) return err;
    unsigned const shift = opt->arg_name ? 2:1;
    return cli_parse(nb_args - shift, args + shift);
}

static char *cli_enum_2_str(unsigned v, char const *values)
{
    char const *start = values;
    while (v-- > 0) {
        // skip a value
        while (*start && *start != '|') start++;
        if (*start == '|') start++;
    }

    if (! *start) return NULL;

    char const *stop = start;
    while (*stop && *stop != '|') stop++;
    return tempstr_printf("%.*s", (int)(stop-start), start);
}

int cli_2_enum(bool case_sensitive, char const *value, ...)
{
    int r = 0;
    va_list ap;
    va_start(ap, value);

    char const *v;
    while (NULL != (v = va_arg(ap, char const *))) {
        if (0 == (case_sensitive ? strcmp : strcasecmp)(value, v)) {
            break;
        }
        r++;
    }
    if (! v) r = -1;

    va_end(ap);
    return r;
}

/*
 * Init
 */

static void print_tabuled(struct cli_opt const *opt, int margin)
{
    static char tabs[] = "                    ";
    if (margin < (int)sizeof(tabs)-1) {
        printf("%s%s", tabs+margin, opt->help);
    } else {
        printf("\n%s%s", tabs, opt->help);
    }
    // display default value
    switch (opt->action) {
        case CLI_CALL:
            break;
        case CLI_SET_UINT:
            printf(" (default: %u)", *opt->u.uint);
            break;
        case CLI_SET_BOOL:
            printf(" (default: %s)", *opt->u.boolean ? "true":"false");
            break;
        case CLI_DUP_STR:
            if (*opt->u.str) printf(" (default: %s)", *opt->u.str);
            break;
        case CLI_SET_ENUM:
            printf(" (default: %s)", cli_enum_2_str(*opt->u.uint, opt->help));
            break;
    }
    puts("");
}

static char const *param_action_2_str(enum cli_action a)
{
    switch (a) {
        case CLI_DUP_STR:
        case CLI_CALL:     return "param";
        case CLI_SET_UINT: return "N";
        case CLI_SET_BOOL: return "t|f";
        case CLI_SET_ENUM: return ""; // not needed since the help has it
    }
    assert(!"Bad cli_action");
    return "";
}

static void help_block(struct cli_bloc const *bloc)
{
    if (bloc->name) {
        printf("\nOptions for %s:\n", bloc->name);
    }
    for (unsigned o = 0; o < bloc->nb_cli_opts; o++) {
        struct cli_opt const *opt = bloc->opts+o;
        int len = printf("    %s%s%s%s%s%s%s",
            opt->arg[0] ? "--" : "",
            opt->arg[0] ? opt->arg[0] : "",
            opt->arg[1] ? ", " : "",
            opt->arg[1] ? "-" : "",
            opt->arg[1] ? opt->arg[1] : "",
            opt->arg_name ? " ":"",
            opt->arg_name ? (
                opt->arg_name != NEEDS_ARG ?
                    opt->arg_name :
                    param_action_2_str(opt->action)
            ) : "");
        print_tabuled(opt, len);
    }
}

static int help_cb(char const unused_ *option)
{
    printf(
        "Junkie %s\n"
        "Copyright 2010 SecurActive\n"
        "Junkie may be distributed under the terms of the GNU Affero General Public Licence;\n"
        "certain other uses are permitted as well.  For details, see the file\n"
        "`COPYING', which is included in the Junkie distribution.\n"
        "There is no warranty, to the extent permitted by law.\n\n",
        version_string);

    struct cli_bloc *bloc;
    TAILQ_FOREACH(bloc, &cli_blocs, entry) {
        help_block(bloc);
    }

    printf("\n");

    exit(EXIT_SUCCESS);
}

static struct cli_opt help_opts[] = {
    { { "help", "h" }, false, "display help", CLI_CALL, { .call = help_cb } },
};

static unsigned inited;
void cli_init(void)
{
    if (inited++) return;
    mutex_init();
    objalloc_init();

    mutex_ctor(&cli_mutex, "CLI");
    cli_register(NULL, help_opts, NB_ELEMS(help_opts));
}

void cli_fini(void)
{
    if (--inited) return;

    cli_unregister(help_opts);
    mutex_dtor(&cli_mutex);

    objalloc_fini();
    mutex_fini();
}

