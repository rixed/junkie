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
#include <junkie/cpp.h>
#include <junkie/tools/miscmacs.h>
#include <junkie/tools/queue.h>
#include <junkie/tools/mutex.h>
#include <junkie/tools/mallocer.h>
#include <junkie/tools/ext.h>   // for version_string
#include <junkie/tools/cli.h>

static char const Id[] = "$Id$";

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

    MALLOCER(cli_blocs);
    struct cli_bloc *bloc = MALLOC(cli_blocs, sizeof(*bloc));
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
        FREE(bloc);
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
    if (opt->need_argument && nb_args < 2) {
        fprintf(stderr, "Option '%s' requires an argument\n", args[0]);
        return -1;
    }

    int err = -1;
    switch (opt->action) {
        case CLI_CALL:
            err = opt->u.call(opt->need_argument ? args[1] : NULL);
            break;
        case CLI_SET_UINT:;
            assert(opt->need_argument);
            char *end;
            *opt->u.uint = strtoul(args[1], &end, 0);
            if (*end != '\0') {
                fprintf(stderr, "Cannot parse numeric option '%s'\n", args[1]);
            } else {
                err = 0;
            }
            break;
        case CLI_SET_BOOL:
            if (! opt->need_argument) { // then the presence of the flag means yes
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
            assert(opt->need_argument);
            *opt->u.str = strdup(args[1]);
            err = *opt->u.str == NULL ? -1:0;
            break;
    }

    if (err) return err;
    unsigned const shift = opt->need_argument ? 2:1;
    return cli_parse(nb_args - shift, args + shift);
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

static void print_tabuled(char const *help, int margin)
{
    static char tabs[] = "                    ";
    if (margin < (int)sizeof(tabs)-1) {
        printf("%s%s\n", tabs+margin, help);
    } else {
        printf("\n%s%s\n", tabs, help);
    }
}

static void help_block(struct cli_bloc const *bloc)
{
    if (bloc->name) {
        printf("\nOptions for %s:\n", bloc->name);
    }
    for (unsigned o = 0; o < bloc->nb_cli_opts; o++) {
        struct cli_opt const *opt = bloc->opts+o;
        int len = printf("    %s%s%s%s%s",
            opt->arg[0] ? "--" : "",
            opt->arg[0] ? opt->arg[0] : "",
            opt->arg[1] ? ", " : "",
            opt->arg[1] ? "-" : "",
            opt->arg[1] ? opt->arg[1] : "");
        print_tabuled(opt->help, len);
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

void cli_init(void)
{
    mutex_ctor(&cli_mutex, "CLI");
    cli_register(NULL, help_opts, NB_ELEMS(help_opts));
}

void cli_fini(void)
{
    cli_unregister(help_opts);
    mutex_dtor(&cli_mutex);
}

