// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef TERM_H_130625
#define TERM_H_130625
#include <junkie/config.h>

/** @file
 * @brief Poor man terminal handling
 */

#define TOPLEFT "\x1B[1;1H"
#define CLEAR   "\x1B[2J"
#define NORMAL  "\x1B[0m"
#define BRIGHT  "\x1B[1m"
#define REVERSE "\x1B[7m"

/// Returns the size of the current terminal
void get_window_size(unsigned *cols, unsigned *rows);

void term_init(void (*cb)(char c));
void term_fini(void);

#endif
