// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef MISC_H_100406
#define MISC_H_100406
#include <stdlib.h>
#include <junkie/config.h>

/** @file
 * @brief Various usefull MACROs
 */

/// Compile time assertion
#define ASSERT_COMPILE(x) do { switch (0) { case 0: case (x):; } } while (0)

#define STRUCT_ALIGNMENT (sizeof(void *))
#define PAD_SIZE(x) (((x + (STRUCT_ALIGNMENT-1))/STRUCT_ALIGNMENT)*STRUCT_ALIGNMENT)

#define CHECK_LAST_FIELD(container, field_name, content) do { \
    ASSERT_COMPILE(sizeof(struct container) <= PAD_SIZE(offsetof(struct container, field_name) + sizeof (content))); \
} while (0)

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
    } while(0)
#else
#   define GUARD(c)
#endif

/// MACROs to fetch from a possibly not aligned address variously sized and byte ordered values
#define BYTE(p, off) ((uint_least64_t)((uint8_t const *)(p))[off])
#define BYTE_D(p, off, dec) (BYTE(p, off) << (dec))
#define READ_U8(p)   ((uint8_t)BYTE(p, 0))
#define READ_U16(p)  ((uint16_t)(BYTE(p, 0) | BYTE_D(p, 1, 8U)))
#define READ_U24(p)  ((uint32_t)(BYTE(p, 0) | BYTE_D(p, 1, 8U) | BYTE_D(p, 2, 16U)))
#define READ_U32(p)  ((uint32_t)(BYTE(p, 0) | BYTE_D(p, 1, 8U) | BYTE_D(p, 2, 16U) | BYTE_D(p, 3, 24U)))
#define READ_U64(p)  ((uint64_t)(BYTE(p, 0) | BYTE_D(p, 1, 8ULL) | BYTE_D(p, 2, 16ULL) | BYTE_D(p, 3, 24ULL) | BYTE_D(p, 4, 32ULL) | BYTE_D(p, 5, 40ULL) | BYTE_D(p, 6, 48ULL) | BYTE_D(p, 7, 56ULL)))
#ifdef WORDS_BIGENDIAN
#   define READ_U16N(p) READ_U16(p)
#   define READ_U24N(p) READ_U24(p)
#   define READ_U32N(p) READ_U32(p)
#   define READ_U64N(p) READ_U64(p)
#else
#   define READ_U16N(p) ((uint16_t)(BYTE_D(p, 0, 8U) | BYTE(p, 1)))
#   define READ_U24N(p) ((uint32_t)(BYTE_D(p, 0, 16U) | BYTE_D(p, 1, 8U) | BYTE(p, 2)))
#   define READ_U32N(p) ((uint32_t)(BYTE_D(p, 0, 24U) | BYTE_D(p, 1, 16U) | BYTE_D(p, 2, 8U) | BYTE(p, 3)))
#   define READ_U64N(p) ((uint64_t)(BYTE_D(p, 0, 56ULL) | BYTE_D(p, 1, 48ULL) | BYTE_D(p, 2, 40ULL) | BYTE_D(p, 3, 32ULL) | BYTE_D(p, 4, 24ULL) | BYTE_D(p, 5, 16ULL) | BYTE_D(p, 6, 8ULL) | BYTE(p, 7)))
#endif

/// Returns a/b, rounded up. Returns a number >= 1
#define CEIL_DIV(a, b) (((a) + (b) - 1)/(b))
/// Returns a/b, rounded to closest.
#define ROUND_DIV(a, b) (((a) + (b/2) - 1)/(b))

#endif
