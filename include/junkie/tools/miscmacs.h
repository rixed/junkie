// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef MISC_H_100406
#define MISC_H_100406
#include <stdlib.h>

/** @file
 * @brief Various usefull MACROs
 */

/// Compile time assertion
#define ASSERT_COMPILE(x) do { switch (0) { case 0: case (x):; } } while (0)

#define STRUCT_ALIGNMENT (sizeof(void *))
#define PAD_SIZE(x) (((x + (STRUCT_ALIGNMENT-1))/STRUCT_ALIGNMENT)*STRUCT_ALIGNMENT)

#define CHECK_LAST_FIELD(container, field_name, content) do { \
    ASSERT_COMPILE(sizeof(struct container) <= PAD_SIZE(offsetof(struct container, field_name) + sizeof (content))); \
} while (0/*CONSTCOND*/)

/// Various utilities
#ifndef MAX
#   define MAX(a, b) (((a) >= (b) ? (a) : (b)))
#   define MIN(a, b) (((a) < (b) ? (a) : (b)))
#endif
#define NB_ELEMS(array) (sizeof array / sizeof array[0])
#define _STRIZE(arg) #arg
#define STRIZE(x)  _STRIZE(x)

/// NIPQUAD/PRINIPQUAD macro pair is usefull to print IP addresses
#define PRINIPQUAD "u.%u.%u.%u"
#define QUAD(ip, q) (((uint8_t *)(ip))[q])
#define NIPQUAD(ip) QUAD(ip, 0), QUAD(ip, 1), QUAD(ip, 2), QUAD(ip, 3)

#define PRINIPQUAD6 "02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"
#define NIPQUAD6(ip) \
    QUAD(ip, 0), QUAD(ip, 1), QUAD(ip, 2), QUAD(ip, 3), \
    QUAD(ip, 4), QUAD(ip, 5), QUAD(ip, 6), QUAD(ip, 7), \
    QUAD(ip, 8), QUAD(ip, 9), QUAD(ip, 10), QUAD(ip, 11), \
    QUAD(ip, 12), QUAD(ip, 13), QUAD(ip, 14), QUAD(ip, 15)

/// Downcast from a subtype to a parent type (ie. from included struct to the struct that includes it)
#ifndef __NCC__ // for some reason ncc chocke on offsetof
#   include <stddef.h>
#   define DOWNCAST(val, member, subtype) ((struct subtype *)((char *)(val) - offsetof(struct subtype, member)))
#else
#   define DOWNCAST(val, member, subtype) ((struct subtype *)(val))
#endif

/// Bit selector
#define BIT(b) (1U << (b))
#define IS_BIT_SET(v, b) (!!((v) & BIT(b)))

/// kind of assert(), but using our own log method
#ifndef NDEBUG
#   define GUARD(c) do { \
        if(! (c)) { \
            SLOG(LOG_ERR, "assertion failed '%s'\n", #c); \
            abort(); \
        } \
    } while(/*CONSTCOND*/0)
#else
#   define GUARD(c)
#endif

#endif
