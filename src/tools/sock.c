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
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>
#include "junkie/tools/log.h"
#include "junkie/tools/sock.h"

#undef LOG_CAT
#define LOG_CAT sock_log_category
LOG_CATEGORY_DEF(sock);

int sock_ctor_client(struct sock *s, char const *host, char const *service)
{
    int res = -1;
    SLOG(LOG_DEBUG, "Construct sock to %s.%s", host, service);

    struct addrinfo *info;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;    // either v4 or v6
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_CANONNAME | AI_V4MAPPED | AI_ADDRCONFIG;

    int err = getaddrinfo(host, service, &hints, &info);
    if (err) {
        SLOG(LOG_ERR, "Cannot getaddrinfo(host=%s, service=%s): %s", service, host, gai_strerror(err));
        // freeaddrinfo ?
        return -1;
    }

    for (struct addrinfo *info_ = info; info_; info_ = info_->ai_next) {
        memset(&s->srv_addr, 0, sizeof(s->srv_addr));
        memcpy(&s->srv_addr, info_->ai_addr, info_->ai_addrlen);
        s->srv_addrlen = info_->ai_addrlen;
        s->srv_family = info_->ai_family;

        char addr[256], srv[256];
        err = getnameinfo(&s->srv_addr, s->srv_addrlen, addr, sizeof(addr), srv, sizeof(srv), NI_DGRAM|NI_NOFQDN|NI_NUMERICSERV|NI_NUMERICHOST);
        if (! err) {
            snprintf(s->name, sizeof(s->name), "%s@%s.%s", info->ai_canonname, addr, srv);
        } else {
            SLOG(LOG_WARNING, "Cannot getnameinfo(): %s", gai_strerror(err));
            snprintf(s->name, sizeof(s->name), "%s@?.%s", info->ai_canonname, service);
        }
        SLOG(LOG_DEBUG, "Trying to use socket %s", s->name);

        s->fd = socket(s->srv_family, SOCK_DGRAM, 0);
        if (s->fd < 0) {
            SLOG(LOG_WARNING, "Cannot socket(): %s", strerror(errno));
            continue;
        }

        // try to connect
        int cfd = connect(s->fd, &s->srv_addr, s->srv_addrlen);
        if (cfd < 0) {
            SLOG(LOG_WARNING, "Cannot connect(): %s", strerror(errno));
            continue;
        }
        (void)close(cfd);

        res = 0;
        break;  // go with this one
    }

    freeaddrinfo(info);
    return res;
}

int sock_ctor_server(struct sock *s, char const *service)
{
    int res = -1;
    SLOG(LOG_DEBUG, "Construct sock for serving %s", service);

    struct addrinfo *info;

    int err = getaddrinfo(NULL, service, NULL, &info);
    if (err) {
        SLOG(LOG_ERR, "Cannot getaddrinfo(service=%s): %s", service, gai_strerror(err));
        // freeaddrinfo ?
        return -1;
    }

    for (struct addrinfo *info_ = info; info_; info_ = info_->ai_next) {
        memset(&s->srv_addr, 0, sizeof(s->srv_addr));
        memcpy(&s->srv_addr, info_->ai_addr, info_->ai_addrlen);
        s->srv_addrlen = info_->ai_addrlen;
        s->srv_family = info_->ai_family;
        snprintf(s->name, sizeof(s->name), "*.%s", service);

        s->fd = socket(s->srv_family, SOCK_DGRAM, 0);
        if (s->fd < 0) {
            SLOG(LOG_WARNING, "Cannot socket(): %s", strerror(errno));
            continue;
        }
        if (0 != bind(s->fd, &s->srv_addr, s->srv_addrlen)) {
            SLOG(LOG_WARNING, "Cannot bind(): %s", strerror(errno));
            (void)close(s->fd);
            s->fd = -1;
            continue;
        } else {
            res = 0;
            break;
        }
    }

    freeaddrinfo(info);
    return res;
}

void sock_dtor(struct sock *s)
{
    SLOG(LOG_DEBUG, "Destruct sock %s", s->name);

    if (s->fd < 0) return;
    int err = close(s->fd);
    s->fd = -1;

    if (err) {
        SLOG(LOG_WARNING, "Cannot close socket to %s: %s", s->name, strerror(errno));
    }
}

int sock_send(struct sock *s, void const *buf, size_t len)
{
    SLOG(LOG_DEBUG, "Sending %zu bytes to %s (fd %d)", len, s->name, s->fd);

    if (-1 == sendto(s->fd, buf, len, MSG_DONTWAIT, &s->srv_addr, s->srv_addrlen)) {
        // FIXME: limit the rate of this error!
        SLOG(LOG_ERR, "Cannot send %zu bytes to %s: %s", len, s->name, strerror(errno));
        return -1;
    }
    return 0;
}

ssize_t sock_recv(struct sock *s, void *buf, size_t maxlen)
{
    SLOG(LOG_DEBUG, "Reading on socket %s (fd %d)", s->name, s->fd);

    ssize_t r = recv(s->fd, buf, maxlen, 0);
    if (r < 0) {
        SLOG(LOG_ERR, "Cannot receive datagram: %s", strerror(errno));
    }

    SLOG(LOG_DEBUG, "read %zd bytes ou of %s", r, s->name);
    return r;
}

bool sock_is_opened(struct sock *s)
{
    return s->fd >= 0;
}

static unsigned inited;
void sock_init(void)
{
    if (inited++) return;
    log_category_sock_init();
}

void sock_fini(void)
{
    if (--inited) return;

    log_category_sock_fini();
}
