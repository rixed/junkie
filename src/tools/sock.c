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
#include <netinet/ip.h>
#include <netdb.h>
#include "junkie/tools/sock.h"
#include "junkie/tools/log.h"
#include "junkie/tools/files.h"

#undef LOG_CAT
#define LOG_CAT sock_log_category
LOG_CATEGORY_DEF(sock);

static int snprint_un_path(char *dest, size_t max_size, char const *service, char const *tag)
{
    return snprintf(dest, max_size, "/tmp/local.%s.%s", service, tag);
}

static int sock_ctor_unix_client(struct sock *s, char const *service)
{
    SLOG(LOG_DEBUG, "Construct client sock to UNIX local %s", service);

    s->fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (s->fd < 0) {
        SLOG(LOG_ERR, "Cannot socket() to UNIX local domain: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_un local;
/*    memset(&local, 0, sizeof(local));
    local.sun_family = AF_UNIX;
    (void)snprint_un_path(local.sun_path, sizeof(local.sun_path), service, "clt");
    if (0 != bind(s->fd, (struct sockaddr *)&local, sizeof(local))) {
        SLOG(LOG_ERR, "Cannot bind() client UNIX path: %s", strerror(errno));
error:
        (void)close(s->fd);
        s->fd = -1;
        return -1;
    }

    s->local = true;
    snprintf(s->name, sizeof(s->name), "%s", local.sun_path);*/

    memset(&local, 0, sizeof(local));
    local.sun_family = AF_UNIX;
    (void)snprint_un_path(local.sun_path, sizeof(local.sun_path), service, "srv");
    s->srv_family = AF_UNIX;
    s->srv_addrlen = sizeof(local);
    memcpy(&s->srv_addr, &local, s->srv_addrlen);

    if (0 != connect(s->fd, &s->srv_addr.gen, s->srv_addrlen)) {
        SLOG(LOG_ERR, "Cannot connect(): %s", strerror(errno));
        (void)close(s->fd);
        s->fd = -1;
        return -1;
    }

    s->local = true;
    s->is_server = false;
    snprintf(s->name, sizeof(s->name), "%s", local.sun_path);

    SLOG(LOG_INFO, "Connected to %s via %s", service, local.sun_path);
    return 0;
}

int sock_ctor_udp_client(struct sock *s, char const *host, char const *service)
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

    s->local = false;
    s->is_server = false;

    for (struct addrinfo *info_ = info; info_; info_ = info_->ai_next) {
        memset(&s->srv_addr, 0, sizeof(s->srv_addr));
        memcpy(&s->srv_addr, info_->ai_addr, info_->ai_addrlen);
        s->srv_addrlen = info_->ai_addrlen;
        s->srv_family = info_->ai_family;

        char addr[256], srv[256];
        err = getnameinfo(&s->srv_addr.gen, s->srv_addrlen, addr, sizeof(addr), srv, sizeof(srv), NI_DGRAM|NI_NOFQDN|NI_NUMERICSERV|NI_NUMERICHOST);
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
        if (0 != connect(s->fd, &s->srv_addr.gen, s->srv_addrlen)) {
            SLOG(LOG_WARNING, "Cannot connect(): %s", strerror(errno));
            continue;
        }

        res = 0;
        break;  // go with this one
    }

    freeaddrinfo(info);
    return res;
}

int sock_ctor_client(struct sock *s, char const *host, char const *service)
{
    if (host && host[0] != '\0') return sock_ctor_udp_client(s, host, service);
    else return sock_ctor_unix_client(s, service);
}

static int sock_ctor_unix_server(struct sock *s, char const *service)
{
    SLOG(LOG_DEBUG, "Construct server sock to UNIX local %s", service);

    struct sockaddr_un local;
    memset(&local, 0, sizeof(local));
    local.sun_family = AF_UNIX;
    (void)snprint_un_path(local.sun_path, sizeof(local.sun_path), service, "srv");
    (void)file_unlink(local.sun_path);
    s->srv_family = AF_UNIX;
    s->srv_addrlen = sizeof(local);
    memcpy(&s->srv_addr, &local, s->srv_addrlen);

    s->fd = socket(s->srv_family, SOCK_DGRAM, 0);
    if (s->fd < 0) {
        SLOG(LOG_ERR, "Cannot socket() to UNIX local domain: %s", strerror(errno));
        return -1;
    }

    if (0 != bind(s->fd, &s->srv_addr.gen, sizeof(local))) {
        SLOG(LOG_ERR, "Cannot bind(): %s", strerror(errno));
        (void)close(s->fd);
        s->fd = -1;
        return -1;
    }

    s->local = true;
    s->is_server = true;
    snprintf(s->name, sizeof(s->name), "%s", local.sun_path);

    SLOG(LOG_INFO, "Connected to %s via %s", service, local.sun_path);
    return 0;
}

static int sock_ctor_udp_server(struct sock *s, char const *service)
{
    int res = -1;
    SLOG(LOG_DEBUG, "Construct sock for serving %s", service);

    struct addrinfo *info;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_PASSIVE;    // listen any interface

    int err = getaddrinfo(NULL, service, &hints, &info);
    if (err) {
        SLOG(LOG_ERR, "Cannot getaddrinfo(service=%s): %s", service, gai_strerror(err));
        // freeaddrinfo ?
        return -1;
    }

    s->local = false;
    s->is_server = true;

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
        if (0 != bind(s->fd, &s->srv_addr.gen, s->srv_addrlen)) {
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

int sock_ctor_server(struct sock *s, bool local, char const *service)
{
    if (! local) return sock_ctor_udp_server(s, service);
    else return sock_ctor_unix_server(s, service);
}

void sock_dtor(struct sock *s)
{
    SLOG(LOG_DEBUG, "Destruct sock %s", s->name);

    if (s->fd < 0) return;
    int err = close(s->fd);
    s->fd = -1;

    if (s->local && s->is_server) {
        (void)file_unlink(s->name);
    }

    if (err) {
        SLOG(LOG_WARNING, "Cannot close socket to %s: %s", s->name, strerror(errno));
    }
}

int sock_send(struct sock *s, void const *buf, size_t len)
{
    SLOG(LOG_DEBUG, "Sending %zu bytes to %s (fd %d)", len, s->name, s->fd);

    if (-1 == sendto(s->fd, buf, len, s->local ? 0:MSG_DONTWAIT, &s->srv_addr.gen, s->srv_addrlen)) {
        // FIXME: limit the rate of this error!
        SLOG(LOG_ERR, "Cannot send %zu bytes to %s: %s", len, s->name, strerror(errno));
        return -1;
    }
    return 0;
}

ssize_t sock_recv(struct sock *s, void *buf, size_t maxlen, struct ip_addr *sender)
{
    SLOG(LOG_DEBUG, "Reading on socket %s (fd %d)", s->name, s->fd);

    struct sockaddr src_addr;
    socklen_t addrlen = sizeof(src_addr);
    ssize_t r = recvfrom(s->fd, buf, maxlen, 0, &src_addr, &addrlen);
    if (r < 0) {
        SLOG(LOG_ERR, "Cannot receive datagram: %s", strerror(errno));
    }
    if (sender) {
        if (addrlen > sizeof(src_addr)) {
            SLOG(LOG_ERR, "Cannot set sender address: size too big (%zu > %zu)", (size_t)addrlen, sizeof(src_addr));
            ip_addr_ctor_from_ip4(sender, 0);
        } else {
            if (s->local || 0 != ip_addr_ctor_from_sockaddr(sender, &src_addr, addrlen)) {
                ip_addr_ctor_from_ip4(sender, 0);
            }
        }
    }

    SLOG(LOG_DEBUG, "read %zd bytes from %s out of %s", r, sender && !s->local ? ip_addr_2_str(sender) : "unknown", s->name);
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
