// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef STRING_140127
#define STRING_140127
#include <junkie/config.h>
#include <junkie/cpp.h>

#ifndef HAVE_STRNSTR
char const *strnstr(char const *haystack, char const *needle, size_t len) pure_;
#endif

// Copy src to dest always NULL terminated.
// Fill at most dest_size bytes including NULL
void copy_string(char *dest, char const *src, size_t dest_size);

// With the advent of UTF8, libc tolower is now useless but for typographers:
inline int tolower_ascii(int c)
{
    if (c >= 'A' && c <= 'Z') return 'a' + (c - 'A');
    return c;
}

inline int toupper_ascii(int c)
{
    if (c >= 'a' && c <= 'z') return 'A' + (c - 'a');
    return c;
}

inline int changecase_ascii(int c)
{
    if (c >= 'A' && c <= 'Z') return 'a' + (c - 'A');
    if (c >= 'a' && c <= 'z') return 'A' + (c - 'a');
    return c;
}

#endif
