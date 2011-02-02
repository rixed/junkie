// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef CPP_H
#define CPP_H
#include <stdlib.h>

/** @file
 * @brief Some GCC attributes that may help to generate fast code.
 *
 * Here are defined :
 *
 * - pure_, hot_, cold_, for functions,
 * - likely_, unlikely_, for if statements,
 * - unused_, to avoid some warnings,
 * - a_la_printf_, to check parameters according to a format string,
 * - packed_, to pack data structures.
 * -sentinel_, to check a variadic list is NULL terminated
 *
 * Of these, only the last one must be implemented in a way or another
 * in order for junkie to work properly.
 */

#ifdef __GNUC__
/// functions which result only depends on inputs be careful of thread safety, etc.
#   define pure_ __attribute__((pure))
#   define hot_ __attribute__((hot))    ///< for often-called function
#   define cold_  __attribute__((cold))    ///< for rarely-called function
#   define likely_(x) __builtin_expect(!!(x), 1) ///< very probable branch in if statement
#   define unlikely_(x)  __builtin_expect(!!(x), 0) ///< very improbable branch in if statement
#   define unused_ __attribute__((__unused__))
#   define a_la_printf_(str_i, arg_i) __attribute__((__format__(__printf__, str_i, arg_i)))
#   define packed_ __attribute__((__packed__))
#   define sentinel_ __attribute__((__sentinel__))
#else
#   define pure_
#   define hot_
#   define cold_
#   define likely_(x)
#   define unlikely_(x)
#   define unused_
#   define a_la_printf_
#   define packed_
#   define sentinel_
#endif

#endif
