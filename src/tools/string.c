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

#include <string.h>
#include "junkie/tools/string.h"
#include <junkie/tools/miscmacs.h>

#ifndef HAVE_STRNSTR
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

void copy_string(char *dest, char const *src, size_t dest_size)
{
    strncpy(dest, src, dest_size);
    if (dest_size)
        dest[dest_size - 1] = '\0';
}

extern inline int tolower_ascii(int c);
extern inline int toupper_ascii(int c);
extern inline int changecase_ascii(int c);
