// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2018, SecurActive.
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
#include <unistd.h>
#include "junkie/tools/objalloc.h"
#include "junkie/netmatch.h"

int netmatch_filter_ctor(struct netmatch_filter *netmatch, char const *libname)
{
    netmatch->libname = objalloc_strdup(libname);
    if (! netmatch->libname) {
        goto err0;
    }

    netmatch->handle = lt_dlopen(libname);
    if (-1 == unlink(libname)) {
        SLOG(LOG_INFO, "Could not delete shared object %s", libname);
    }
    if (! netmatch->handle) {
        SLOG(LOG_CRIT, "Cannot load netmatch shared object %s: %s", libname, lt_dlerror());
        goto err1;
    }

    netmatch->match_fun = lt_dlsym(netmatch->handle, "match");
    if (! netmatch->match_fun) {
        SLOG(LOG_CRIT, "Cannot find match function in netmatch shared object %s", libname);
        goto err2;
    }

    unsigned const *num_regs_ptr = lt_dlsym(netmatch->handle, "num_registers");
    if (! num_regs_ptr) {
        SLOG(LOG_CRIT, "Cannot find num_registers symbol in netmatch shared object %s", libname);
        goto err2;
    }

    netmatch->num_registers = *num_regs_ptr;
    if (netmatch->num_registers > 0) {
        netmatch->regfile = objalloc_nice(netmatch->num_registers * sizeof(*netmatch->regfile), "netmatches");
        if (! netmatch->regfile) goto err3;
        memset(netmatch->regfile, 0, netmatch->num_registers * sizeof(*netmatch->regfile));
    } else {
        netmatch->regfile = NULL;
    }

    return 0;
err3:
    if (netmatch->regfile) {
        objfree(netmatch->regfile);
        netmatch->regfile = NULL;
    }
err2:
    if (netmatch->handle) {
        (void)lt_dlclose(netmatch->handle);
        netmatch->handle = NULL;
    }
err1:
    if (netmatch->libname) {
        objfree(netmatch->libname);
        netmatch->libname = NULL;
    }
err0:
    return -1;
}

void netmatch_filter_dtor(struct netmatch_filter *netmatch)
{
    if (netmatch->regfile) {
        objfree(netmatch->regfile);
        netmatch->regfile = NULL;
    }

    if (netmatch->libname) {
        objfree(netmatch->libname);
        netmatch->libname = NULL;
    }

    if (netmatch->handle) {
        (void)lt_dlclose(netmatch->handle);
        netmatch->handle = NULL;
    }
}
