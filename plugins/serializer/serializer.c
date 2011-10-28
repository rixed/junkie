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
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <regex.h>
#include "junkie/cpp.h"
#include "junkie/capfile.h"
#include "junkie/tools/cli.h"
#include "junkie/tools/sock.h"
#include "junkie/tools/serialize.h"
#include "junkie/proto/proto.h"

static char *opt_dest_name = "localhost";
static char *opt_dest_port = "28999";
static struct sock sock;
static bool inited = false;

static void init_cnx(void)
{
    (void)sock_ctor_client(&sock, opt_dest_name, opt_dest_port);
    inited = true;
}

static void fini_cnx(void)
{
    if (inited) sock_dtor(&sock);
}

int parse_callback(struct proto_info const *info, size_t unused_ cap_len, uint8_t const unused_ *packet)
{
    static bool inited = false;
    if (! inited) {
        init_cnx();
        inited = true;
    }

    if (! sock_is_opened(&sock)) return 0;

    /* Since there is a largest protocol stack, there is no need to check for any size in the serialization process, IFF
     * this buffer is larger than the corresponding info stack. */
    uint8_t buf[MSG_MAX_SIZE];
    uint8_t *ptr = buf;
    serialize_1(&ptr, MSG_PROTO_INFO);  // provision for other kind of messages that may be sent to the same target (ie. dumper)
    serialize_proto_stack(&ptr, (buf+NB_ELEMS(buf))-ptr, info);

    (void)sock_send(&sock, buf, (char *)ptr - (char *)buf);
    return 0;
}

// Extension of the command line:
static struct cli_opt sender_opts[] = {
    { { "dest", NULL }, true, "peer where to send infos", CLI_DUP_STR, { .str = &opt_dest_name } },
    { { "port", NULL }, true, "destination port",         CLI_DUP_STR, { .str = &opt_dest_port } },
};

void on_load(void)
{
    SLOG(LOG_INFO, "Loading sender");
    cli_register("Sender plugin", sender_opts, NB_ELEMS(sender_opts));
}

void on_unload(void)
{
    SLOG(LOG_INFO, "Unloading sender");
    cli_unregister(sender_opts);
    fini_cnx();
}
