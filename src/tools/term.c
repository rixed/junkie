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
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <termios.h>
#include "junkie/config.h"
#include "junkie/tools/log.h"
#include "junkie/tools/mutex.h"
#include "junkie/tools/term.h"

static int quit = 0;
static __thread bool from_keyctrl = false;

// A tool to get terminal window size
void get_window_size(unsigned *cols, unsigned *rows)
{
    struct winsize ws;
    if (-1 == ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws)) {
        SLOG(LOG_WARNING, "Cannot get terminal size: %s", strerror(errno));
        // TODO: try getenv COLUMNS and LINES?
        ws.ws_row = 25;
        ws.ws_col = 80;
    }
    if (cols) *cols = ws.ws_col;
    if (rows) *rows = ws.ws_row;
}

/*
 * Key reading thread
 */

// read keys and change use flags
static void *keyctrl_thread(void *cb_)
{
    from_keyctrl = true;
    void (*cb)(char key) = cb_;
    set_thread_name("J-keyctrl");

    while (! quit) {
        unsigned char c;
        int r = read(0, &c, 1);
        pthread_testcancel();
        if (r == 0) {
            SLOG(LOG_ERR, "Cannot read(stdin): end of file");
            return NULL;
        } else if (r < 1) {
            SLOG(LOG_ERR, "Cannot read(stdin): %s", strerror(errno));
            return NULL;
        }
        // Call user function with key c
        cb(c);
    }

    return NULL;
}

/*
 * Init
 */

static pthread_t keyctrl_pth;
static struct termios termios_orig;

void term_init(void (*cb)(char c))
{
    tcgetattr(0, &termios_orig);
    struct termios termios_new = termios_orig;
//    cfmakeraw(&termios_new);
    termios_new.c_lflag &= ~(ECHO | ICANON);    // Disable echo and make chars available immediately
    tcsetattr(0, TCSANOW, &termios_new);

    if (0 != pthread_create(&keyctrl_pth, NULL, keyctrl_thread, cb)) {
        SLOG(LOG_CRIT, "Cannot spawn keyboard controler thread");
    }
}

void term_fini(void)
{
    if (from_keyctrl) {
        quit = 1;
    } else {
        (void)pthread_cancel(keyctrl_pth);
        (void)pthread_join(keyctrl_pth, NULL);
    }

    tcsetattr(0, TCSANOW, &termios_orig);
}
