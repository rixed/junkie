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
#include <unistd.h> // for getpid()
#include <regex.h>
#include "junkie/cpp.h"
#include "junkie/tools/cli.h"
#include "junkie/tools/sock.h"
#include "junkie/tools/mutex.h"
#include "junkie/proto/serialize.h"
#include "junkie/proto/proto.h"
#include "junkie/proto/capfile.h"

static char *opt_dest_name = "localhost";
static char *opt_dest_port = "28999";
static unsigned opt_msg_size = 1500;
static struct sock *sock;
static bool inited = false;
/* Since there is a largest protocol stack, there is no need to check for any size in the serialization process, IFF
 * this buffer is larger than the corresponding info stack. */
static uint8_t *ser_buf;
static unsigned ser_cursor;
static uint64_t ser_nb_msgs;
static uint32_t ser_source;
static struct mutex ser_buf_lock;   // protect ser_buf and ser_cursor

static void ser_send(void)
{
    sock->ops->send(sock, ser_buf, ser_cursor);
    ser_cursor = 0;
}

/* Some init is not performed until we receive some traffic.
 * Actually, we just want to wait for the command line parsing is over. */
static void ser_init(void)
{
    if (inited) return;
    ser_source = getpid();
    sock = sock_udp_client_new(opt_dest_name, opt_dest_port);
    if (! sock) {
        SLOG(LOG_ERR, "Cannot connect to %s:%s", opt_dest_name, opt_dest_port);
        return;
    }
    ASSERT_COMPILE(MSG_MAX_SIZE <= DATAGRAM_MAX_SIZE);
    if (opt_msg_size < MSG_MAX_SIZE) {
        SLOG(LOG_ERR, "Made serializer buffer "STRIZE(MSG_MAX_SIZE)" bytes large");
        opt_msg_size = MSG_MAX_SIZE;
    } else if (opt_msg_size > DATAGRAM_MAX_SIZE) {
        SLOG(LOG_ERR, "Make serializer buffer "STRIZE(DATAGRAM_MAX_SIZE)" bytes large");
        opt_msg_size = DATAGRAM_MAX_SIZE;
    }
    ser_buf = malloc(opt_msg_size);
    if (! ser_buf) {
        SLOG(LOG_ERR, "Cannot malloc serializer buffer (%u bytes)", opt_msg_size);
        // so be it
    }
    inited = true;
}

static void ser_fini(void)
{
    if (inited) {
        if (ser_cursor > 0) {
            SLOG(LOG_DEBUG, "Flushing last message");
            ser_send();
        }
        sock->ops->del(sock);
        if (ser_buf) {
            free(ser_buf);
            ser_buf = NULL;
        }
    }
}

static void pkt_callback(struct proto_subscriber unused_ *s, struct proto_info const *info, size_t unused_ cap_len, uint8_t const unused_ *packet, struct timeval const *now)
{
    mutex_lock(&ser_buf_lock);

    ser_init();

    if (! sock_is_opened(sock) || !ser_buf) goto quit;

    uint8_t *ptr = ser_buf + ser_cursor;
    serialize_1(&ptr, MSG_PROTO_INFO);
    serialize_4(&ptr, ser_source);
    serialize_proto_stack(&ptr, info, now);
    ser_nb_msgs ++;
    if (0 == (ser_nb_msgs % 32)) {  // from time to time, insert some stats about how many packets were sent by this source
        serialize_1(&ptr, MSG_PROTO_STATS);
        serialize_4(&ptr, ser_source);
        serialize_8(&ptr, ser_nb_msgs);
    }
    ser_cursor = ptr - ser_buf;
    SLOG(LOG_DEBUG, "New buffer cursor = %u", ser_cursor);
    assert(ser_cursor < opt_msg_size);

    if (opt_msg_size - ser_cursor < MSG_MAX_SIZE) ser_send();

quit:
    mutex_unlock(&ser_buf_lock);
}

// Extension of the command line:
static struct cli_opt serializer_opts[] = {
    { { "dest", NULL },     "hostname", "peer where to send infos", CLI_DUP_STR,  { .str = &opt_dest_name } },
    { { "port", NULL },     "port",     "destination port",         CLI_DUP_STR,  { .str = &opt_dest_port } },
    { { "msg-size", NULL }, NEEDS_ARG,  "max message size",         CLI_SET_UINT, { .uint = &opt_msg_size } },
};

static struct proto_subscriber subscription;

void on_load(void)
{
    SLOG(LOG_INFO, "Loading serializer");
    cli_register("Serializer plugin", serializer_opts, NB_ELEMS(serializer_opts));
    mutex_ctor(&ser_buf_lock, "Serializer buffer lock");
    proto_pkt_subscriber_ctor(&subscription, pkt_callback);
}

void on_unload(void)
{
    SLOG(LOG_INFO, "Unloading serializer");
    proto_pkt_subscriber_dtor(&subscription);
    cli_unregister(serializer_opts);
    ser_fini();
    mutex_dtor(&ser_buf_lock);
}
