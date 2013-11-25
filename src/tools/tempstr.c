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
#include <pthread.h>
#include "junkie/config.h"
#include "junkie/tools/tempstr.h"
#include "junkie/tools/miscmacs.h"
#include "junkie/cpp.h"

static __thread unsigned next;
static __thread char bufs[256][TEMPSTR_SIZE];

char *tempstr(void)
{
    if (++next >= NB_ELEMS(bufs)) next = 0;
    bufs[next][0] = '\0';
    return bufs[next];
}

char *tempstr_printf(char const *fmt, ...)
{
    char *str = tempstr();
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(str, TEMPSTR_SIZE, fmt, ap);
    va_end(ap);
    return str;
}

// FIXME: move me into tools/string ?

#ifndef HAVE_STRNSTR
#include <string.h>
#define BUF_MAXSZ 4096

char const *strnstr(char const *haystack, char const *needle, size_t len)
{
    if (len >= BUF_MAXSZ) return NULL;

    static __thread char buf[BUF_MAXSZ];
    memcpy(buf, haystack, len);
    buf[len] = 0;

    char *found = strstr(buf, needle);

    if (!found)
        return NULL;

    // return a pointer to the char in the string which match the computed offset
    size_t offset = found - buf;

    return &haystack[offset];
}
#endif

