// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef TERM_H_130625
#define TERM_H_130625
#include <junkie/config.h>

/** @file
 * @brief Poor man terminal handling
 */

void term_init(void (*cb)(char c));
void term_fini(void);

#endif
