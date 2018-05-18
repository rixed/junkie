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
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
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

char *tempstr_hex(uint8_t const *buf, size_t size)
{
    char *str = tempstr();
    int len = snprintf(str, TEMPSTR_SIZE, "0x");
    for (unsigned o = 0; o < size && len < TEMPSTR_SIZE; o++) {
        len += snprintf(str+len, TEMPSTR_SIZE-len, "%02x", buf[o]);
    }

    return str;
}

char const *tempstr_smallint(unsigned n)
{
    static char const *const ret[] = {
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
        "10", "11", "12", "13", "14", "15", "16", "17", "18", "19" };
    assert(n < NB_ELEMS(ret));
    return ret[n];
}
