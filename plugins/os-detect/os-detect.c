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
/* Plugin that displays the operating systems it can detect. */
#include <stdlib.h>
#include <assert.h>
#include "junkie/cpp.h"
#include "junkie/proto/proto.h"
#include "junkie/proto/os-detect.h"
#include "junkie/proto/ip.h"
#include "junkie/proto/tcp.h"

#undef LOG_CAT
#define LOG_CAT os_detect_log_category
LOG_CATEGORY_DEF(os_detect);

static void tcp_callback(struct proto_subscriber unused_ *subscription, struct proto_info const *last, size_t unused_ tot_cap_len, uint8_t const unused_ *tot_packet, struct timeval const unused_ *ts)
{
    struct tcp_proto_info const *tcp = DOWNCAST(last, info, tcp_proto_info);
    ASSIGN_INFO_CHK(ip, last, );

    unsigned os = os_detect(ip, tcp);
    if (os) printf("%s: %s\n", ip_addr_2_str(ip->key.addr+0), os_name(os));
}

/*
 * Init
 */

static struct proto_subscriber subscription;

void on_load(void)
{
    log_category_os_detect_init();
    SLOG(LOG_INFO, "Loading OS-detect plugin");
    hook_subscriber_ctor(&proto_tcp->hook, &subscription, tcp_callback);
}

void on_unload(void)
{
    SLOG(LOG_INFO, "Unloading OS-detect");
    hook_subscriber_dtor(&proto_tcp->hook, &subscription);
    log_category_os_detect_fini();
}

