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
#include <dirent.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "junkie/tools/miscmacs.h"
#include "junkie/tools/sock.h"
#include "junkie/tools/log.h"
#include "junkie/tools/files.h"
#include "junkie/tools/ext.h"
#include "junkie/tools/mallocer.h"
#include "junkie/tools/serialization.h"

#undef LOG_CAT
#define LOG_CAT sock_log_category
LOG_CATEGORY_DEF(sock);

/** We cannot easilly use objalloc from here (due to module recursive dep),
 * So we use straight mallocer */
static MALLOCER_DEF(sock_mallocer);

static struct ip_addr local_ip;

union sockaddr_gen {
    struct sockaddr a;
    struct sockaddr_storage placeholder;
};

static bool bind_v6_as_v6 = true;
EXT_PARAM_RW(bind_v6_as_v6, "bind-v6-as-v6", bool, "Bind IPv6 sockets for V6 addresses only (IPV6_V6ONLY socket option)")

/*
 * Functions on socks
 */

static void sock_ctor(struct sock *s, struct sock_ops const *ops)
{
    SLOG(LOG_DEBUG, "Construct sock@%p", s);
    s->ops = ops;
    s->receiver = NULL;
    s->user_data = NULL;
    bench_event_ctor(&s->sending, tempstr_printf("Sending to %p", s));  // to bad we have not always the name at this point
}

static void sock_dtor(struct sock *s)
{
    SLOG(LOG_DEBUG, "Destruct sock %s", s->name);
    bench_event_dtor(&s->sending);
}

/*
 * Inet sock (used by UDP and TCP)
 */

struct sock_inet {
    struct sock sock;
    int fd[5];  // up to 5 listened sockets (for servers, clients use only the first)
    unsigned nb_fds;
    // everything required to rebuild the socket in case something goes wrong
    char *host;   // strdupped
    char *service;    // strdupped
    size_t buf_size;
    int type;   // SOCK_STREAM/SOCK_DGRAM
    time_t last_connect;
};

static void sock_inet_disconnect_all(struct sock_inet *s)
{
    for (unsigned f = 0; f < s->nb_fds; f++) {
        SLOG(LOG_DEBUG, "Closing fd %d", s->fd[f]);
        file_close(s->fd[f]);
        s->fd[f] = -1;
    }
    s->nb_fds = 0;
}

static int sock_inet_client_connect(struct sock_inet *s)
{
    SLOG(LOG_INFO, "Connecting %s:%s", s->host, s->service);

    // start by closing what we still have
    sock_inet_disconnect_all(s);

    // don't attempt repeatedly
    time_t now = time(NULL);
#   define SOCK_QUARANTINE_SECS 3
    if (now < s->last_connect + SOCK_QUARANTINE_SECS) {
        SLOG(LOG_DEBUG, "Won't attempt to connect right now");
        return -1;
    }
    s->last_connect = now;

    int res = -1;
    char const *proto = s->type == SOCK_STREAM ? "tcp":"udp";

    struct addrinfo *info;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;    // either v4 or v6
    hints.ai_socktype = s->type;
    hints.ai_flags = AI_CANONNAME | AI_V4MAPPED | AI_ADDRCONFIG;

    int err = getaddrinfo(s->host, s->service, &hints, &info);
    if (err) {
        SLOG(LOG_ERR, "Cannot getaddrinfo(host=%s, service=%s): %s", s->service, s->host, gai_strerror(err));
        // freeaddrinfo ?
        return -1;
    }

    union sockaddr_gen srv_addr;
    socklen_t srv_addrlen;
    int srv_family;

    for (struct addrinfo *info_ = info; info_; info_ = info_->ai_next) {
        memset(&srv_addr, 0, sizeof(srv_addr));
        memcpy(&srv_addr, info_->ai_addr, info_->ai_addrlen);
        srv_addrlen = info_->ai_addrlen;
        srv_family = info_->ai_family;

        char addr[256], srv[256];
        err = getnameinfo(&srv_addr.a, srv_addrlen, addr, sizeof(addr), srv, sizeof(srv), NI_DGRAM|NI_NOFQDN|NI_NUMERICSERV|NI_NUMERICHOST);
        if (! err) {
            snprintf(s->sock.name, sizeof(s->sock.name), "%s://%s@%s:%s", proto, info_->ai_canonname, addr, srv);
        } else {
            SLOG(LOG_WARNING, "Cannot getnameinfo(): %s", gai_strerror(err));
            snprintf(s->sock.name, sizeof(s->sock.name), "%s://%s@?:%s", proto, info_->ai_canonname, s->service);
        }
        SLOG(LOG_DEBUG, "Trying to use socket %s", s->sock.name);

        s->fd[0] = socket(srv_family, s->type, 0);
        if (s->fd[0] < 0) {
            SLOG(LOG_WARNING, "Cannot socket(): %s", strerror(errno));
            continue;
        }

        // try to connect
        if (0 != connect(s->fd[0], &srv_addr.a, srv_addrlen)) {
            file_close(s->fd[0]);
            SLOG(LOG_WARNING, "Cannot connect(): %s", strerror(errno));
            continue;
        }
        // Finish construction of s
        res = 0;
        s->nb_fds = 1;
        SLOG(LOG_INFO, "Connected to %s", s->sock.name);
        break;  // go with this one
    }

    if (s->buf_size) set_rcvbuf(s->fd[0], s->buf_size);

    freeaddrinfo(info);
    return res;
}

static int sock_inet_client_ctor(struct sock_inet *s, char const *host, char const *service, size_t buf_size, int type, struct sock_ops const *ops)
{
    char const *proto = type == SOCK_STREAM ? "tcp":"udp";
    SLOG(LOG_DEBUG, "Construct sock to %s://%s:%s", proto, host, service);

    sock_ctor(&s->sock, ops);
    s->host = STRDUP(sock_mallocer, host);
    s->service = STRDUP(sock_mallocer, service);
    s->buf_size = buf_size;
    s->type = type;
    s->last_connect = 0;
    s->nb_fds = 0;

    return sock_inet_client_connect(s);
}

static int sock_inet_server_ctor(struct sock_inet *s, char const *service, size_t buf_size, int type, struct sock_ops const *ops)
{
    char const *proto = type == SOCK_STREAM ? "tcp":"udp";
    SLOG(LOG_DEBUG, "Construct sock for serving %s/%s", service, proto);

    struct addrinfo *info;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_PASSIVE;    // listen any interface
    hints.ai_family = AF_UNSPEC;    // either v4 or v6
    hints.ai_socktype = type;

    int err = getaddrinfo(NULL, service, &hints, &info);
    if (err) {
        SLOG(LOG_ERR, "Cannot getaddrinfo(service=%s): %s", service, gai_strerror(err));
        // freeaddrinfo ?
        return -1;
    }

    union sockaddr_gen srv_addr;
    socklen_t srv_addrlen;
    int srv_family;

    s->nb_fds = 0;
    for (struct addrinfo *info_ = info; info_ && s->nb_fds < NB_ELEMS(s->fd); info_ = info_->ai_next) {
        memset(&srv_addr, 0, sizeof(srv_addr));
        memcpy(&srv_addr, info_->ai_addr, info_->ai_addrlen);
        srv_addrlen = info_->ai_addrlen;
        srv_family = info_->ai_family;
        snprintf(s->sock.name, sizeof(s->sock.name), "%s://*:%s", proto, service);

        s->fd[s->nb_fds] = socket(srv_family, type, 0);
        if (s->fd[s->nb_fds] < 0) {
            SLOG(LOG_WARNING, "Cannot socket(): %s", strerror(errno));
            continue;
        }

        int one = 1;
        if (srv_family == AF_INET6 && bind_v6_as_v6) {
            /* Do what I say instead of what Linux thinks I should do
             * (ie, work around poor default value for bindv6only) */
            SLOG(LOG_DEBUG, "binding IPv6 only when binding IPv6");
            if (0 != setsockopt(s->fd[s->nb_fds], IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one))) {
                SLOG(LOG_ERR, "Cannot setsockopt(%s, IPV6_V6ONLY): %s", service, strerror(errno));
            }
        }
        if (0 != setsockopt(s->fd[s->nb_fds], SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))) {
            SLOG(LOG_ERR, "Cannot setsockopt(%s, SO_REUSEADDR): %s", service, strerror(errno));
        }

        if (0 != bind(s->fd[s->nb_fds], &srv_addr.a, srv_addrlen)) {
            SLOG(LOG_WARNING, "Cannot bind(%s): %s", service, strerror(errno));
            file_close(s->fd[s->nb_fds]);
            s->fd[s->nb_fds] = -1;
            continue;
        } else {
            if (buf_size) set_rcvbuf(s->fd[s->nb_fds], buf_size);
            SLOG(LOG_DEBUG, "Bound TCP sock on fd %d", s->fd[s->nb_fds]);
            s->nb_fds ++;
            continue;
        }
    }

    if (s->nb_fds > 0) {
        // Finish construction
        sock_ctor(&s->sock, ops);
        SLOG(LOG_INFO, "Serving %s", s->sock.name);
    }
    freeaddrinfo(info);

    return s->nb_fds > 0 ? 0:-1;
}

static void sock_inet_dtor(struct sock_inet *s)
{
    sock_inet_disconnect_all(s);
    sock_dtor(&s->sock);
    if (s->host) {
        FREE(s->host);
        s->host = NULL;
    }
    if (s->service) {
        FREE(s->service);
        s->service = NULL;
    }
}

static bool sock_inet_is_opened(struct sock_inet *s)
{
    return s->nb_fds > 0;
}

/*
 * UDP sockets
 */

struct sock_udp {
    struct sock_inet inet;
};

static int sock_udp_send(struct sock *s_, void const *buf, size_t len)
{
    struct sock_inet *i_ = DOWNCAST(s_, sock, sock_inet);

    SLOG(LOG_DEBUG, "Sending %zu bytes to %s (fd %d)", len, s_->name, i_->fd[0]);

    uint64_t const start = bench_event_start();
    if (i_->nb_fds < 1 || -1 == send(i_->fd[0], buf, len, MSG_DONTWAIT)) {
        TIMED_SLOG(LOG_ERR, "Cannot send %zu bytes into %s: %s", len, s_->name, strerror(errno));
        if (0 != sock_inet_client_connect(i_)) {
            return -1;
        }
        return sock_udp_send(s_, buf, len);
    }
    bench_event_stop(&s_->sending, start);
    return 0;
}

static ssize_t my_recvfrom(int fd, uint8_t *buf, size_t bufsz, struct ip_addr *sender)
{
    union {
        struct sockaddr a;
        struct sockaddr_storage placeholder;
    } src_addr;
    socklen_t addrlen = sizeof(src_addr);
    ssize_t r = recvfrom(fd, buf, bufsz, 0, &src_addr.a, &addrlen);
    if (r < 0) return r;
    if (! sender) return r;

    if (addrlen > sizeof(src_addr)) {
        SLOG(LOG_ERR, "Cannot set sender address: size too big (%zu > %zu)", (size_t)addrlen, sizeof(src_addr));
        *sender = local_ip;
    } else {
        if (0 != ip_addr_ctor_from_sockaddr(sender, &src_addr.a, addrlen)) {
            *sender = local_ip;
        }
    }
    return r;
}

static int sock_udp_recv(struct sock *s_, fd_set *set)
{
    struct sock_inet *i_ = DOWNCAST(s_, sock, sock_inet);

    for (unsigned fdi = 0; fdi < i_->nb_fds; fdi++) {
        if (! FD_ISSET(i_->fd[fdi], set)) continue;

        SLOG(LOG_DEBUG, "Reading on socket %s (fd %d)", s_->name, i_->fd[fdi]);

        uint8_t buf[SOCK_MAX_MSG_SIZE];
        struct ip_addr sender;
        ssize_t r = my_recvfrom(i_->fd[fdi], buf, sizeof(buf), &sender);
        if (r < 0) {
            TIMED_SLOG(LOG_ERR, "Cannot receive datagram from %s: %s", s_->name, strerror(errno));
            return r;
        }

        SLOG(LOG_DEBUG, "read %zd bytes out of %s", r, s_->name);

        int err = s_->receiver ?
            s_->receiver(s_, MIN((size_t)r, sizeof(buf)), buf, &sender) : 0;
        if (err) return err;
    }

    return 0;
}

static int sock_udp_set_fd(struct sock *s_, fd_set *set)
{
    struct sock_inet *i_ = DOWNCAST(s_, sock, sock_inet);
    int max = -1;
    for (unsigned fdi = 0; fdi < i_->nb_fds; fdi++) {
        max = MAX(max, i_->fd[fdi]);
        FD_SET(i_->fd[fdi], set);
    }
    return max;
}

static bool sock_udp_is_opened(struct sock *s_)
{
    struct sock_inet *i_ = DOWNCAST(s_, sock, sock_inet);
    return sock_inet_is_opened(i_);
}

static void sock_udp_dtor(struct sock_udp *s)
{
    sock_inet_dtor(&s->inet);
}

static void sock_udp_del(struct sock *s_)
{
    struct sock_inet *i_ = DOWNCAST(s_, sock, sock_inet);
    struct sock_udp *s = DOWNCAST(i_, inet, sock_udp);
    sock_udp_dtor(s);
    FREE(s);
}

static struct sock_ops sock_udp_ops = {
    .send = sock_udp_send,
    .recv = sock_udp_recv,
    .set_fd = sock_udp_set_fd,
    .is_opened = sock_udp_is_opened,
    .del = sock_udp_del,
};

static int sock_udp_client_ctor(struct sock_udp *s, char const *host, char const *service, size_t buf_size)
{
    return sock_inet_client_ctor(&s->inet, host, service, buf_size, SOCK_DGRAM, &sock_udp_ops);
}

struct sock *sock_udp_client_new(char const *host, char const *service, size_t buf_size)
{
    struct sock_udp *s = MALLOC(sock_mallocer, sizeof(*s));
    if (! s) return NULL;
    if (0 != sock_udp_client_ctor(s, host, service, buf_size)) {
        FREE(s);
        return NULL;
    }
    return &s->inet.sock;
}

static int sock_udp_server_ctor(struct sock_udp *s, char const *service, size_t buf_size)
{
    return sock_inet_server_ctor(&s->inet, service, buf_size, SOCK_DGRAM, &sock_udp_ops);
}

struct sock *sock_udp_server_new(char const *service, size_t buf_size)
{
    struct sock_udp *s = MALLOC(sock_mallocer, sizeof(*s));
    if (! s) return NULL;
    if (0 != sock_udp_server_ctor(s, service, buf_size)) {
        FREE(s);
        return NULL;
    }
    return &s->inet.sock;
}

/*
 * TCP sockets
 */

typedef uint32_t msg_len;

struct sock_tcp {
    struct sock_inet inet;
    bool threaded;  // whether or not each client must be read by a new thread
    // The folowing is used only by the server:
#   define NB_MAX_TCP_CLIENTS 10    // should be good enough for most uses
    struct sock_tcp_client {
        int fd; // <0 when free
        struct ip_addr addr;
        size_t prev_read;   // what was already read of next message
        uint8_t read_buf[SOCK_MAX_MSG_SIZE];    // the read buffer for messages
        // The following are only used when threaded
        pthread_t pth;
        struct sock *sock;  // backlink so we can call receiver fun
    } clients[NB_MAX_TCP_CLIENTS];
};

static int sock_tcp_send(struct sock *s_, void const *buf, size_t len)
{
    struct sock_inet *i_ = DOWNCAST(s_, sock, sock_inet);

    SLOG(LOG_DEBUG, "Sending %zu bytes to %s (fd %d)", len, s_->name, i_->fd[0]);

    msg_len msg_len = len;
    struct iovec iov[2] = {
        { .iov_base = &msg_len, .iov_len = sizeof(msg_len), },
        { .iov_base = (void *)buf, .iov_len = len, },
    };
    uint64_t const start = bench_event_start();
    if (i_->nb_fds < 1 || -1 == file_writev(i_->fd[0], iov, NB_ELEMS(iov))) {
        TIMED_SLOG(LOG_ERR, "Cannot send %zu bytes into %s: %s", len, s_->name, strerror(errno));
        if (0 != sock_inet_client_connect(i_)) {
            return -1;
        }
        return sock_tcp_send(s_, buf, len);
    }
    bench_event_stop(&s_->sending, start);
    return 0;
}

static int tcp_read(struct sock_tcp_client *client, bool threaded)
{
    SLOG(LOG_DEBUG, "Reading on fd %d (cnx to %s)", client->fd, ip_addr_2_str(&client->addr));

    // start or continue reading previous msg.
    if (client->prev_read < sizeof(msg_len)) {
        // We still have not read the msg length
        if (threaded) enable_cancel();
        ssize_t const r = read(client->fd, client->read_buf + client->prev_read, sizeof(msg_len) - client->prev_read);
        if (threaded) disable_cancel();
        if (r < 0) {
            SLOG(LOG_ERR, "Cannot read a message size from %d: %s", client->fd, strerror(errno));
fail:
            return -1;
        } else if (r == 0) {
            SLOG(LOG_INFO, "closing connection %d", client->fd);
            goto fail;
        }
        client->prev_read += (size_t)r;
    }

    // now if we have read the whole msg_len, proceed with reading the msg itself
    msg_len len;
    memcpy(&len, client->read_buf, sizeof(msg_len));

    if (len > sizeof(client->read_buf)-sizeof(msg_len)) {
        SLOG(LOG_ERR, "Message size from %d (%zu) bigger than max expected message size (" STRIZE(SOCK_MAX_MSG_SIZE) " - msg_len)!", client->fd, (size_t)len);
        goto fail;
    } else {
        SLOG(LOG_DEBUG, "Will read msg payload of %zu bytes", (size_t)len);
    }
    // then the msg (notice we may have already received the beginning of it)
    size_t const rest = (sizeof(msg_len) + len) - client->prev_read;
    if (threaded) enable_cancel();
    ssize_t const r = read(client->fd, client->read_buf + client->prev_read, rest);
    if (threaded) disable_cancel();
    if (r < 0) {
        SLOG(LOG_ERR, "Cannot read %zu bytes from %d: %s", rest, client->fd, strerror(errno));
        goto fail;
    } else if (r == 0) {
        SLOG(LOG_INFO, "closing connection %d (2)", client->fd);
        goto fail;
    } else {
        SLOG(LOG_DEBUG, "Just read %zd bytes", r);
    }

    if ((size_t)r < rest) {
        client->prev_read += (size_t)r;
    } else {
        SLOG(LOG_DEBUG, "read msg of %zu bytes out of %d", (size_t)len, client->fd);
        int err = client->sock->receiver ?
            client->sock->receiver(client->sock, len, client->read_buf + sizeof(msg_len), &local_ip) : 0;
        client->prev_read = 0;
        if (err) return err;
    }
    return 0;
}

static void guile_thread_cleanup(void *client_)
{
    struct sock_tcp_client *client = client_;
    if (client->fd >= 0) {
        file_close(client->fd);
        client->fd = -1;
    }
}

static void *reader_thread(void *client_)
{
    struct sock_tcp_client *client = client_;
    set_thread_name(tempstr_printf("J-read%d-%s", client->fd, ip_addr_2_str(&client->addr)));
    disable_cancel();

    scm_dynwind_begin(0);
    scm_dynwind_unwind_handler(guile_thread_cleanup, client, SCM_F_WIND_EXPLICITLY);

    // Just read until EOF or any other error
    while (client->fd >= 0) {
        if (0 != tcp_read(client, true)) {
            file_close(client->fd);
            client->fd = -1;
        }
    }

    scm_dynwind_end();

    return NULL;
}

static void *start_guile_reader(void *client_)
{
    return scm_with_guile(reader_thread, client_);
}


static int sock_tcp_recv(struct sock *s_, fd_set *set)
{
    struct sock_inet *i_ = DOWNCAST(s_, sock, sock_inet);
    struct sock_tcp *s = DOWNCAST(i_, inet, sock_tcp);
    unsigned new_c = NB_ELEMS(s->clients);

    // Note: a sock_inet listens on several sockets (for instance, ipv4 + ipv6)
    for (unsigned fdi = 0; fdi < i_->nb_fds; fdi++) {
        // Handle new connections
        if (! FD_ISSET(i_->fd[fdi], set)) continue;

        // accept the connection
        union sockaddr_gen addr;
        socklen_t addrlen = sizeof(addr);
        int fd = accept(i_->fd[fdi], &addr.a, &addrlen);
        if (fd < 0) {
            SLOG(LOG_ERR, "Cannot accept new connection to %s: %s", s_->name, strerror(errno));
            continue;
        }
        // save it in a free client slot
        for (new_c = 0; new_c < NB_ELEMS(s->clients); new_c++) {
            if (s->clients[new_c].fd < 0) break;
        }
        if (new_c == NB_ELEMS(s->clients)) {
            SLOG(LOG_ERR, "Cannot accept new connection to %s: no more available slots", s_->name);
            file_close(fd);
            continue;
        }
        // construct the client
        s->clients[new_c].fd = fd;
        ip_addr_ctor_from_sockaddr(&s->clients[new_c].addr, &addr.a, addrlen);
        s->clients[new_c].prev_read = 0;
        SLOG(LOG_NOTICE, "New connection from %s to %s on fd %d", ip_addr_2_str(&s->clients[new_c].addr), s_->name, fd);
        if (s->threaded) {  // spawn a new thread to read this one
            int err = pthread_create(&s->clients[new_c].pth, NULL, start_guile_reader, s->clients+new_c);
            if (! err) {
                // FIXME: proper ctor + mutex
                s->clients[new_c].sock = s_;
            } else {
                SLOG(LOG_ERR, "Cannot start reader thread on fd %d: %s", fd, strerror(err));
                file_close(fd);
                s->clients[new_c].fd = -1;
            }
        }
    }

    if (!s->threaded) {
        // Now do we have actual incoming datas?
        for (unsigned c = 0; c < NB_ELEMS(s->clients); c++) {
            if (c == new_c) continue;   // avoids asking for a fd we didn't set (although this would work on glibc)
            if (s->clients[c].fd < 0 || !FD_ISSET(s->clients[c].fd, set)) continue;

            if (0 != tcp_read(s->clients+c, false)) {
                file_close(s->clients[c].fd);
                s->clients[c].fd = -1;
            }
        }
    }

    return 0;
}

static int sock_tcp_set_fd(struct sock *s_, fd_set *set)
{
    struct sock_inet *i_ = DOWNCAST(s_, sock, sock_inet);
    struct sock_tcp *s = DOWNCAST(i_, inet, sock_tcp);
    int max = -1;
    SLOG(LOG_DEBUG, "Setting TCP fds (%u listeners)", i_->nb_fds);
    for (unsigned fdi = 0; fdi < i_->nb_fds; fdi++) {
        SLOG(LOG_DEBUG, "Setting TCP listener fd %d", i_->fd[fdi]);
        max = MAX(max, i_->fd[fdi]);
        FD_SET(i_->fd[fdi], set);
    }
    if (! s->threaded) {
        for (unsigned c = 0; c < NB_ELEMS(s->clients); c++) {
            if (s->clients[c].fd >= 0) {
                max = MAX(max, s->clients[c].fd);
                FD_SET(s->clients[c].fd, set);
            }
        }
    }
    return max;
}

static bool sock_tcp_is_opened(struct sock *s_)
{
    struct sock_inet *i_ = DOWNCAST(s_, sock, sock_inet);
    return sock_inet_is_opened(i_);
}

static void sock_tcp_dtor(struct sock_tcp *s)
{
    SLOG(LOG_DEBUG, "Destruct TCP sock");
    sock_inet_dtor(&s->inet);
    for (unsigned c = 0; c < NB_ELEMS(s->clients); c++) {
        if (s->clients[c].fd >= 0) {
            if (s->threaded) {
                SLOG(LOG_DEBUG, "Cancelling reader thread");
                (void)pthread_cancel(s->clients[c].pth);
                (void)pthread_join(s->clients[c].pth, NULL);
            }
            file_close(s->clients[c].fd);
            s->clients[c].fd = -1;
        }
    }
}

static void sock_tcp_del(struct sock *s_)
{
    struct sock_inet *i_ = DOWNCAST(s_, sock, sock_inet);
    struct sock_tcp *s = DOWNCAST(i_, inet, sock_tcp);
    sock_tcp_dtor(s);
    FREE(s);
}

static struct sock_ops sock_tcp_ops = {
    .send = sock_tcp_send,
    .recv = sock_tcp_recv,
    .set_fd = sock_tcp_set_fd,
    .is_opened = sock_tcp_is_opened,
    .del = sock_tcp_del,
};

static int sock_tcp_client_ctor(struct sock_tcp *s, char const *host, char const *service, size_t buf_size)
{
    int err = sock_inet_client_ctor(&s->inet, host, service, buf_size, SOCK_STREAM, &sock_tcp_ops);
    if (err) return err;

    for (unsigned c = 0; c < NB_ELEMS(s->clients); c++) {
        s->clients[c].fd = -1;
    }
    return 0;
}

struct sock *sock_tcp_client_new(char const *host, char const *service, size_t buf_size)
{
    struct sock_tcp *s = MALLOC(sock_mallocer, sizeof(*s));
    if (! s) return NULL;
    if (0 != sock_tcp_client_ctor(s, host, service, buf_size)) {
        FREE(s);
        return NULL;
    }
    return &s->inet.sock;
}

static int sock_tcp_server_ctor(struct sock_tcp *s, char const *service, size_t buf_size, bool threaded)
{
    for (unsigned c = 0; c < NB_ELEMS(s->clients); c++) {
        s->clients[c].fd = -1;
    }

    s->threaded = threaded;
    int err = sock_inet_server_ctor(&s->inet, service, buf_size, SOCK_STREAM, &sock_tcp_ops);
    if (err) return err;

    for (unsigned fds = 0; fds < s->inet.nb_fds; fds++) {
        SLOG(LOG_DEBUG, "listen on fd %d", s->inet.fd[fds]);
        if (listen(s->inet.fd[fds], 3) < 0) {
            SLOG(LOG_ERR, "Cannot listen on socket %s: %s", s->inet.sock.name, strerror(errno));
            return -1;
        }
    }

    return 0;
}

struct sock *sock_tcp_server_new(char const unused_ *service, size_t unused_ buf_size, bool threaded)
{
    struct sock_tcp *s = MALLOC(sock_mallocer, sizeof(*s));
    if (! s) return NULL;
    if (0 != sock_tcp_server_ctor(s, service, buf_size, threaded)) {
        FREE(s);
        return NULL;
    }
    return &s->inet.sock;
}

/*
 * Unix domain socket
 */

struct sock_unix {
    struct sock sock;
    int fd;
    char file[PATH_MAX];
    bool is_server; // the server is responsible for unlinking the file
};

// SAME AS SOCK_UDP_SEND
static int sock_unix_send(struct sock *s_, void const *buf, size_t len)
{
    struct sock_unix *s = DOWNCAST(s_, sock, sock_unix);

    SLOG(LOG_DEBUG, "Sending %zu bytes to %s (fd %d)", len, s->sock.name, s->fd);

    uint64_t const start = bench_event_start();
    if (-1 == send(s->fd, buf, len, 0)) {
        TIMED_SLOG(LOG_ERR, "Cannot send %zu bytes into %s: %s", len, s->sock.name, strerror(errno));
        return -1;
    }
    bench_event_stop(&s_->sending, start);
    return 0;
}

static int sock_unix_recv(struct sock *s_, fd_set *set)
{
    struct sock_unix *s = DOWNCAST(s_, sock, sock_unix);
    if (! FD_ISSET(s->fd, set)) return 0;

    SLOG(LOG_DEBUG, "Reading on socket %s (fd %d)", s->sock.name, s->fd);

    uint8_t buf[SOCK_MAX_MSG_SIZE];
    ssize_t r = recv(s->fd, buf, sizeof(buf), 0);
    if (r < 0) {
        TIMED_SLOG(LOG_ERR, "Cannot receive datagram from %s: %s", s->sock.name, strerror(errno));
        return -1;
    }

    SLOG(LOG_DEBUG, "read %zd bytes out of %s", r, s->sock.name);
    return s_->receiver ?
        s_->receiver(s_, r, buf, &local_ip) : 0;
}

static int sock_unix_set_fd(struct sock *s_, fd_set *set)
{
    struct sock_unix *s = DOWNCAST(s_, sock, sock_unix);
    FD_SET(s->fd, set);
    return s->fd;
}

static bool sock_unix_is_opened(struct sock *s_)
{
    struct sock_unix *s = DOWNCAST(s_, sock, sock_unix);
    return s->fd != -1;
}

static void sock_unix_dtor(struct sock_unix *s)
{
    sock_dtor(&s->sock);
    file_close(s->fd);
    if (s->is_server) {
        (void)file_unlink(s->file);
    }
}

static void sock_unix_del(struct sock *s_)
{
    struct sock_unix *s = DOWNCAST(s_, sock, sock_unix);
    sock_unix_dtor(s);
    FREE(s);
}

static struct sock_ops sock_unix_ops = {
    .send = sock_unix_send,
    .recv = sock_unix_recv,
    .set_fd = sock_unix_set_fd,
    .is_opened = sock_unix_is_opened,
    .del = sock_unix_del,
};

static int sock_unix_client_ctor(struct sock_unix *s, char const *file)
{
    SLOG(LOG_DEBUG, "Construct client sock to unix://127.0.0.1:%s", file);

    s->fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (s->fd < 0) {
        SLOG(LOG_ERR, "Cannot socket() to UNIX local domain: %s", strerror(errno));
        return -1;
    }

    snprintf(s->file, sizeof(s->file), "%s", file);

    struct sockaddr_un local;
    memset(&local, 0, sizeof(local));
    local.sun_family = AF_UNIX;
    (void)snprintf(local.sun_path, sizeof(local.sun_path), "%s", file);

    if (0 != connect(s->fd, (struct sockaddr*)&local, sizeof(local))) {
        SLOG(LOG_ERR, "Cannot connect(): %s", strerror(errno));
        file_close(s->fd);
        s->fd = -1;
        return -1;
    }

    snprintf(s->sock.name, sizeof(s->sock.name), "unix://127.0.0.1/%s", file);
    s->is_server = false;

    sock_ctor(&s->sock, &sock_unix_ops);
    SLOG(LOG_INFO, "Connected to %s", s->sock.name);
    return 0;
}

struct sock *sock_unix_client_new(char const *file)
{
    struct sock_unix *s = MALLOC(sock_mallocer, sizeof(*s));
    if (! s) return NULL;
    if (0 != sock_unix_client_ctor(s, file)) {
        FREE(s);
        return NULL;
    }
    return &s->sock;
}

static int sock_unix_server_ctor(struct sock_unix *s, char const *file)
{
    SLOG(LOG_DEBUG, "Construct server for unix://127.0.0.1:%s", file);

    struct sockaddr_un local;
    memset(&local, 0, sizeof(local));
    local.sun_family = AF_UNIX;
    (void)snprintf(local.sun_path, sizeof(local.sun_path), "%s", file);
    (void)file_unlink(local.sun_path);

    s->fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (s->fd < 0) {
        SLOG(LOG_ERR, "Cannot socket() to UNIX local domain: %s", strerror(errno));
        return -1;
    }

    if (0 != bind(s->fd, &local, sizeof(local))) {
        SLOG(LOG_ERR, "Cannot bind(): %s", strerror(errno));
        file_close(s->fd);
        s->fd = -1;
        return -1;
    }

    snprintf(s->sock.name, sizeof(s->sock.name), "unix://127.0.0.1/%s", local.sun_path);
    s->is_server = true;
    sock_ctor(&s->sock, &sock_unix_ops);

    SLOG(LOG_INFO, "Serving %s", s->sock.name);
    return 0;
}

struct sock *sock_unix_server_new(char const *file)
{
    struct sock_unix *s = MALLOC(sock_mallocer, sizeof(*s));
    if (! s) return NULL;
    if (0 != sock_unix_server_ctor(s, file)) {
        FREE(s);
        return NULL;
    }
    return &s->sock;
}

/*
 * File "sockets"
 */

struct sock_file {
    struct sock sock;
    char dir[PATH_MAX];
    off_t max_file_size;
    int fd; // of the last fd opened
    unsigned id;    // the id of the file in fd
    bool server;
};

// FIXME: race condition if several clients writes into new files: while we look on direntries the max file can be filled by another client
static int sock_file_open(struct sock_file *s, unsigned max_n)
{
    DIR *dir = opendir(s->dir);
    if (! dir) {
        SLOG(LOG_ERR, "Cannot open directory %s: %s", s->dir, strerror(errno));
        return -1;
    }

    unsigned long n;
    char *end;
    struct dirent de, *ptr;
    int err = -1;
    while (1) {
        if (0 != readdir_r(dir, &de, &ptr)) {
            SLOG(LOG_ERR, "Cannot readdir(%s): %s", s->dir, strerror(errno));
            goto quit;
        }
        if (!ptr) break;

        SLOG(LOG_DEBUG, "Scanning %s", de.d_name);
        n = strtoul(de.d_name, &end, 0);
        if (*end == '\0') max_n = MAX(max_n, n);
    }

    // open/create the max file
    char *path = tempstr_printf("%s/%u", s->dir, max_n);
    s->fd = file_open(path, (s->server ? O_RDONLY:O_WRONLY)|O_CREAT|O_CLOEXEC);
    if (s->fd < 0) goto quit;
    s->id = max_n;
    err = 0;
quit:
    (void)closedir(dir);
    return err;
}

static int sock_file_send(struct sock *s_, void const *buf, size_t len)
{
    struct sock_file *s = DOWNCAST(s_, sock, sock_file);

    if (s->fd < 0 || (s->max_file_size > 0 && file_offset(s->fd) >= s->max_file_size)) {
        if (0 != sock_file_open(s, s->fd >= 0 ? s->id+1 : 0)) return -1;
    }

    SLOG(LOG_DEBUG, "Writing %zu bytes to %s (fd %d)", len, s->sock.name, s->fd);

    msg_len msg_len = len;
    struct iovec iov[2] = {
        { .iov_base = &msg_len, .iov_len = sizeof(msg_len), },
        { .iov_base = (void *)buf, .iov_len = len, },
    };
    uint64_t const start = bench_event_start();
    int err = file_writev(s->fd, iov, NB_ELEMS(iov));
    if (!err) bench_event_stop(&s_->sending, start);
    return err;
}

static int sock_file_recv(struct sock *s_, fd_set *set)
{
    struct sock_file *s = DOWNCAST(s_, sock, sock_file);

    if (s->fd < 0 || !FD_ISSET(s->fd, set)) return 0;

    SLOG(LOG_DEBUG, "Reading on socket %s (fd %d)", s->sock.name, s->fd);

    if (s->fd < 0 || (s->max_file_size > 0 && file_offset(s->fd) >= s->max_file_size)) {
        if (0 != sock_file_open(s, s->fd >= 0 ? s->id+1 : 0)) return -1;
    }

    msg_len len;
    ssize_t r = file_read(s->fd, &len, sizeof(len));
    if (r < 0) {
        SLOG(LOG_ERR, "Cannot read a message size from %s: skip file!", s->sock.name);
skip:
        file_close(s->fd);
        s->fd = -1;
        s->id ++;
        return -1;
    }

    if (len > SOCK_MAX_MSG_SIZE) {
        SLOG(LOG_ERR, "Message size from %s (%zu) bigger than max expected message size (" STRIZE(SOCK_MAX_MSG_SIZE) "), skip file!", s->sock.name, (size_t)len);
        goto skip;
    }
    uint8_t buf[len];
    r = file_read(s->fd, buf, len);
    if (r < 0) {
        SLOG(LOG_ERR, "Cannot read a message of %zd bytes from %s: skip file!", (size_t)len, s->sock.name);
        goto skip;
    }

    SLOG(LOG_DEBUG, "read %zd bytes out of %s", r, s->sock.name);
    return s_->receiver ?
        s_->receiver(s_, len, buf, &local_ip) : 0;
}

static int sock_file_set_fd(struct sock *s_, fd_set *set)
{
    struct sock_file *s = DOWNCAST(s_, sock, sock_file);
    if (s->fd < 0 || (s->max_file_size > 0 && file_offset(s->fd) >= s->max_file_size)) {
        if (0 != sock_file_open(s, s->fd >= 0 ? s->id+1 : 0)) return -1;
    }
    FD_SET(s->fd, set);
    return s->fd;
}

static bool sock_file_is_opened(struct sock unused_ *s_)
{
    return true;
}

static void sock_file_dtor(struct sock_file *s)
{
    sock_dtor(&s->sock);
    if (s->fd >= 0) {
        file_close(s->fd);
        s->fd = -1;
    }
}

static void sock_file_del(struct sock *s_)
{
    struct sock_file *s = DOWNCAST(s_, sock, sock_file);
    sock_file_dtor(s);
    FREE(s);
}

static struct sock_ops sock_file_ops = {
    .send = sock_file_send,
    .recv = sock_file_recv,
    .set_fd = sock_file_set_fd,
    .is_opened = sock_file_is_opened,
    .del = sock_file_del,
};

static int sock_file_ctor(struct sock_file *s, char const *dir, off_t max_file_size, bool server)
{
    sock_ctor(&s->sock, &sock_file_ops);
    snprintf(s->sock.name, sizeof(s->sock.name), "file://127.0.0.1/%s", dir);
    snprintf(s->dir, sizeof(s->dir), "%s", dir);
    if (0 != mkdir_all(s->dir, false)) return -1;
    s->max_file_size = max_file_size;
    s->fd = -1;
    s->id = 0;
    s->server = server;
    return 0;
}

struct sock *sock_file_client_new(char const *dir, off_t max_file_size)
{
    struct sock_file *s = MALLOC(sock_mallocer, sizeof(*s));
    if (! s) return NULL;
    if (0 != sock_file_ctor(s, dir, max_file_size, false)) {
        FREE(s);
        return NULL;
    }
    return &s->sock;
}

static int sock_file_server_ctor(struct sock_file *s, char const *dir, off_t max_file_size)
{
    return sock_file_ctor(s, dir, max_file_size, true);
}

struct sock *sock_file_server_new(char const *dir, off_t max_file_size)
{
    struct sock_file *s = MALLOC(sock_mallocer, sizeof(*s));
    if (! s) return NULL;
    if (0 != sock_file_server_ctor(s, dir, max_file_size)) {
        FREE(s);
        return NULL;
    }
    return &s->sock;
}

/*
 * Buffered sockets
 */

#define LEN_BYTES 4  // size of the len field, in bytes
#define SERIALIZE serialize_4
#define DESERIALIZE deserialize_4

static int sock_buf_flush(struct sock_buf *s)
{
    if (s->out_sz == 0) return 0;
    SLOG(LOG_DEBUG, "Flushing buf of %zu bytes", s->out_sz);
    int ret = s->ll_sock->ops->send(s->ll_sock, s->out, s->out_sz);
    s->out_sz = 0;
    return ret;
}

static int sock_buf_send(struct sock *s_, void const *buf, size_t len)
{
    struct sock_buf *s = DOWNCAST(s_, sock, sock_buf);

    if (LEN_BYTES + len >= s->mtu) {
        SLOG(LOG_ERR, "Can't buffer %zu bytes into MTU of %zu", len, s->mtu);
        return -1;
    }

    if (s->out_sz + LEN_BYTES + len > s->mtu) (void)sock_buf_flush(s);

    uint8_t *ser_buf = s->out + s->out_sz;
    SERIALIZE(&ser_buf, len);
    memcpy(ser_buf, buf, len);

    s->out_sz += LEN_BYTES + len;

    SLOG(LOG_DEBUG, "Adding %zu bytes into buf (now: %zu bytes)", len, s->out_sz);

    if (s->out_sz <= s->mtu) return 0;

    return sock_buf_flush(s);
}

static int sock_buf_receiver(struct sock *ll_sock, size_t len, uint8_t const *buf, struct ip_addr const *sender)
{
    struct sock_buf *s = ll_sock->user_data;

    SLOG(LOG_DEBUG, "Reading a buffer of %zu bytes from socket %s", len, ll_sock->name);

    while (len > 0) {
        // We have a msg left in receive buffer
        if (len < LEN_BYTES) {
            SLOG(LOG_ERR, "Received a trunced PDU?");
            return -1;
        }
        size_t msg_len = DESERIALIZE(&buf);
        len -= LEN_BYTES;
        if (msg_len > len) {
            SLOG(LOG_ERR, "Received badly packed msg of %zu bytes in PDU of %zu bytes", msg_len, len);
            return -1;
        }
        SLOG(LOG_DEBUG, "read %zd bytes out of %s", msg_len, ll_sock->name);

        int err = s->sock.receiver ?
            s->sock.receiver(&s->sock, msg_len, buf, sender) : 0;
        if (err) return -1;

        buf += msg_len;
        len -= msg_len;
    }

    return 0;
}

static int sock_buf_recv(struct sock *s_, fd_set *set)
{
    struct sock_buf *s = DOWNCAST(s_, sock, sock_buf);
    return s->ll_sock->ops->recv(s->ll_sock, set);
}

static int sock_buf_set_fd(struct sock *s_, fd_set *set)
{
    struct sock_buf *s = DOWNCAST(s_, sock, sock_buf);
    return s->ll_sock->ops->set_fd(s->ll_sock, set);
}

static bool sock_buf_is_opened(struct sock *s_)
{
    struct sock_buf *s = DOWNCAST(s_, sock, sock_buf);
    return s->ll_sock->ops->is_opened(s->ll_sock);
}

void sock_buf_dtor(struct sock_buf *s)
{
    sock_buf_flush(s);
    if (s->ll_sock) {
        s->ll_sock->ops->del(s->ll_sock);
        s->ll_sock = NULL;
    }
    sock_dtor(&s->sock);
    FREE(s->out);
}

static void sock_buf_del(struct sock *s_)
{
    struct sock_buf *s = DOWNCAST(s_, sock, sock_buf);
    sock_buf_dtor(s);
    FREE(s);
}

static struct sock_ops sock_buf_ops = {
    .send = sock_buf_send,
    .recv = sock_buf_recv,
    .set_fd = sock_buf_set_fd,
    .is_opened = sock_buf_is_opened,
    .del = sock_buf_del,
};

int sock_buf_ctor(struct sock_buf *s, size_t mtu, struct sock *ll_sock)
{
    s->out = MALLOC(sock_mallocer, mtu);
    if (! s->out) {
        return -1;
    }

    sock_ctor(&s->sock, &sock_buf_ops);
    snprintf(s->sock.name, sizeof(s->sock.name), "%s (buf up to %zu)", ll_sock->name, mtu);

    s->mtu = mtu;
    s->ll_sock = ll_sock;
    s->ll_sock->receiver = sock_buf_receiver;
    s->ll_sock->user_data = s;
    s->out_sz = 0;

    return 0;
}

struct sock *sock_buf_new(size_t mtu, struct sock *ll_sock)
{
    struct sock_buf *s = MALLOC(sock_mallocer, sizeof(*s));
    if (! s) return NULL;
    if (0 != sock_buf_ctor(s, mtu, ll_sock)) {
        FREE(s);
        return NULL;
    }
    return &s->sock;
}


/*
 * Tools
 */

int sock_select_single(struct sock *sock, fd_set *set)
{
    FD_ZERO(set);
    int max_fd = sock->ops->set_fd(sock, set);
    while (1) {
        SLOG(LOG_DEBUG, "Wait for %s to become readable", sock->name);
        int s = select(max_fd+1, set, NULL, NULL, 0);
        if (s < 0 && errno != EINTR) {
            SLOG(LOG_ERR, "Cannot select() on %s: %s", sock->name, strerror(errno));
            return -1;
        }
        if (s > 0) break;
    }

    return 0;
}


/*
 * The Sock Smob
 */

static scm_t_bits sock_smob_tag;
static SCM udp_sym;
static SCM tcp_sym;
static SCM ttcp_sym;
static SCM unix_sym;
static SCM file_sym;
static SCM buf_sym;
static SCM client_sym;
static SCM server_sym;

static size_t sock_smob_free(SCM smob)
{
    struct sock *s = (struct sock *)SCM_SMOB_DATA(smob);
    s->ops->del(s);
    return 0;
}

static int sock_smob_print(SCM smob, SCM port, scm_print_state unused_ *pstate)
{
    struct sock *s = (struct sock *)SCM_SMOB_DATA(smob);
    scm_puts("#<sock ", port);
    scm_puts(s->name, port);
    scm_puts(">", port);
    return 1;
}

static void sock_smob_init(void)
{
    sock_smob_tag = scm_make_smob_type("sock", sizeof(struct sock)); // hopefully, guile won't do anything with this size, which poorly reflect the actual size _we_ will alloc depending on the type

    scm_set_smob_free(sock_smob_tag, sock_smob_free);
    scm_set_smob_print(sock_smob_tag, sock_smob_print);
}

struct sock *scm_to_sock(SCM sock_)
{
    scm_assert_smob_type(sock_smob_tag, sock_);
    return (struct sock *)SCM_SMOB_DATA(sock_);
}

// Caller must have started a scm-dynwind region
static char *scm_to_service(SCM p)
{
    char *service;
    if (scm_is_string(p)) {
        service = scm_to_locale_string(p);
        scm_dynwind_free(service);
    } else {
        service = tempstr_printf("%u", scm_to_int(p));
    }
    return service;
}

// Caller must have started a scm-dynwind region
static struct sock *make_sock_udp_client(SCM server_, SCM service_, SCM buf_size_)
{
    char *server = scm_to_locale_string(server_);
    scm_dynwind_free(server);

    char *service = scm_to_service(service_);
    size_t buf_size = SCM_BNDP(buf_size_) ? scm_to_size_t(buf_size_) : 0;

    struct sock *s = sock_udp_client_new(server, service, buf_size);

    if (! s) {
        scm_throw(scm_from_latin1_symbol("cannot-create-sock"),
                  SCM_EOL);
    }

    return s;
}

// Caller must have started a scm-dynwind region
static struct sock *make_sock_udp_server(SCM service_, SCM buf_size_)
{
    char *service = scm_to_service(service_);
    size_t buf_size = SCM_BNDP(buf_size_) ? scm_to_size_t(buf_size_) : 0;

    struct sock *s = sock_udp_server_new(service, buf_size);

    if (! s) {
        scm_throw(scm_from_latin1_symbol("cannot-create-sock"),
                  SCM_EOL);
    }

    return s;
}

// Caller must have started a scm-dynwind region
static struct sock *make_sock_udp(SCM type_, SCM p2_, SCM p3_, SCM p4_)
{
    if (! scm_is_symbol(type_)) goto inval_type;

    if (scm_is_eq(type_, server_sym)) {
        return make_sock_udp_server(p2_, p3_);
    } else if (scm_is_eq(type_, client_sym)) {
        return make_sock_udp_client(p2_, p3_, p4_);
    }

inval_type:
    scm_throw(scm_from_latin1_symbol("invalid-argument"),
              scm_list_1(type_));
    return NULL;    // never reached
}

// Caller must have started a scm-dynwind region
static struct sock *make_sock_tcp_client(SCM server_, SCM service_, SCM buf_size_)
{
    char *server = scm_to_locale_string(server_);
    scm_dynwind_free(server);

    char *service = scm_to_service(service_);
    size_t buf_size = SCM_BNDP(buf_size_) ? scm_to_size_t(buf_size_) : 0;

    struct sock *s = sock_tcp_client_new(server, service, buf_size);

    if (! s) {
        scm_throw(scm_from_latin1_symbol("cannot-create-sock"),
                  SCM_EOL);
    }

    return s;
}

// Caller must have started a scm-dynwind region
static struct sock *make_sock_tcp_server(SCM service_, SCM buf_size_, bool threaded)
{
    char *service = scm_to_service(service_);
    size_t buf_size = SCM_BNDP(buf_size_) ? scm_to_size_t(buf_size_) : 0;

    struct sock *s = sock_tcp_server_new(service, buf_size, threaded);

    if (! s) {
        scm_throw(scm_from_latin1_symbol("cannot-create-sock"),
                  SCM_EOL);
    }

    return s;
}

// Caller must have started a scm-dynwind region
static struct sock *make_sock_tcp(SCM type_, SCM p2_, SCM p3_, SCM p4_, bool threaded)
{
    if (! scm_is_symbol(type_)) goto inval_type;

    if (scm_is_eq(type_, server_sym)) {
        return make_sock_tcp_server(p2_, p3_, threaded);
    } else if (scm_is_eq(type_, client_sym)) {
        return make_sock_tcp_client(p2_, p3_, p4_);
    }

inval_type:
    scm_throw(scm_from_latin1_symbol("invalid-argument"),
              scm_list_1(type_));
    return NULL;    // never reached
}

// Caller must have started a scm-dynwind region
static struct sock *make_sock_unix(SCM p1_, SCM p2_)
{
    SCM file_ = p1_;
    SCM type_ = p2_;
    if (! scm_is_string(file_)) {
        file_ = p2_;
        type_ = p1_;
        if (SCM_UNBNDP(file_) || !scm_is_string(file_)) {
            scm_throw(scm_from_latin1_symbol("missing-argument"),
                      scm_list_1(scm_from_latin1_symbol("file")));
        }
    }

    if (SCM_BNDP(type_) && !scm_is_symbol(type_)) {
inval_type:
        scm_throw(scm_from_latin1_symbol("invalid-argument"),
                  scm_list_1(type_));
    }

    struct sock *s = NULL;
    char *file = scm_to_locale_string(file_);
    scm_dynwind_free(file);

    if (SCM_BNDP(type_) && scm_is_eq(type_, server_sym)) {
        s = sock_unix_server_new(file);
    } else {
        // client by default
        if (SCM_BNDP(type_) && !scm_is_eq(type_, client_sym)) {
            goto inval_type;
        }
        s = sock_unix_client_new(file);
    }

    if (! s) {
        scm_throw(scm_from_latin1_symbol("cannot-create-sock"),
                  SCM_EOL);
    }

    return s;
}

// Caller must have started a scm-dynwind region
static struct sock *make_sock_file(SCM type_, SCM file_, SCM max_size_)
{
    if (SCM_UNBNDP(file_)) {
        scm_throw(scm_from_latin1_symbol("missing-argument"), SCM_EOL);
    }

    if (!scm_is_symbol(type_)) {
inv_type:
        scm_throw(scm_from_latin1_symbol("invalid-argument"),
                  scm_list_1(type_));
    }

    struct sock *s = NULL;
    char *file = scm_to_locale_string(file_);
    scm_dynwind_free(file);

    off_t max_size = SCM_BNDP(max_size_) ? scm_to_uint64(max_size_) : 0;
    if (scm_is_eq(type_, server_sym)) {
        s = sock_file_server_new(file, max_size);
    } else if (scm_is_eq(type_, client_sym)) {
        s = sock_file_client_new(file, max_size);
    } else {
        goto inv_type;
    }

    if (! s) {
        scm_throw(scm_from_latin1_symbol("cannot-create-sock"),
                  SCM_EOL);
    }

    return s;
}

// Caller must have started a scm-dynwind region
static struct sock *make_sock_buf(SCM mtu_, SCM ll_sock_)
{
    unsigned mtu = scm_to_uint(mtu_);
    scm_assert_smob_type(sock_smob_tag, ll_sock_);
    scm_gc_protect_object(ll_sock_);    // FIXME: store a ref to it in the SMOB so that it's deleted when this buffered sock is deleted?
    struct sock *ll_sock = (struct sock *)SCM_SMOB_DATA(ll_sock_);

    struct sock *s = sock_buf_new(mtu, ll_sock);

    if (! s) {
        scm_throw(scm_from_latin1_symbol("cannot-create-sock"),
                  SCM_EOL);
    }

    return s;
}

static struct ext_function sg_make_sock;
static SCM g_make_sock(SCM type, SCM p1, SCM p2, SCM p3, SCM p4)
{
    /* p1, p2, p3 and p4 signification depends on the type.
     * See make-sock documentation below for usage examples. */
    // FIXME: This function is too high level and should been implemented in guile
    scm_dynwind_begin(0);
    struct sock *s = NULL;
    if (scm_is_eq(type, udp_sym)) {
        s = make_sock_udp(p1, p2, p3, p4);
    } else if (scm_is_eq(type, tcp_sym)) {
        s = make_sock_tcp(p1, p2, p3, p4, false);
    } else if (scm_is_eq(type, ttcp_sym)) {
        s = make_sock_tcp(p1, p2, p3, p4, true);
    } else if (scm_is_eq(type, unix_sym)) {
        s = make_sock_unix(p1, p2);
    } else if (scm_is_eq(type, file_sym)) {
        s = make_sock_file(p1, p2, p3);
    } else if (scm_is_eq(type, buf_sym)) {
        s = make_sock_buf(p1, p2);
    } else {
        scm_throw(scm_from_latin1_symbol("invalid-argument"),
                  scm_list_1(p1));
    }

    assert(s);

    SCM smob;
    SCM_NEWSMOB(smob, sock_smob_tag, s);    // guaranteed to return

    scm_dynwind_end();
    return smob;
}

static struct ext_function sg_sock_is_opened;
static SCM g_sock_is_opened(SCM sock_)
{
    scm_assert_smob_type(sock_smob_tag, sock_);
    struct sock *sock = (struct sock *)SCM_SMOB_DATA(sock_);

    return scm_from_bool(sock->ops->is_opened(sock));
}

static struct ext_function sg_sock_send;
static SCM g_sock_send(SCM sock_, SCM str_)
{
    scm_assert_smob_type(sock_smob_tag, sock_);
    struct sock *sock = (struct sock *)SCM_SMOB_DATA(sock_);

    size_t len;
    char *str = scm_to_latin1_stringn(str_, &len);
    int res = sock->ops->send(sock, str, len);
    free(str);

    return res >= 0 ? SCM_BOOL_T : SCM_BOOL_F;
}

static SCM test_res;
#define G_SOCK_RECEIVER_BUF_SIZE 1024
static int g_sock_receiver(struct sock unused_ *s_, size_t len, uint8_t const *buf, struct ip_addr const unused_ *sender)
{
    test_res = scm_cons(scm_from_latin1_stringn((char const *)buf, len), test_res);
    return 0;
}

static struct ext_function sg_sock_recv;
static SCM g_sock_recv(SCM sock_)
{
    scm_assert_smob_type(sock_smob_tag, sock_);
    struct sock *sock = (struct sock *)SCM_SMOB_DATA(sock_);

    fd_set set;
    if (0 != sock_select_single(sock, &set)) return SCM_BOOL_F;

    if (! sock->receiver) sock->receiver = g_sock_receiver;
    test_res = SCM_EOL;
    int err = sock->ops->recv(sock, &set);
    if (err) return SCM_BOOL_F;

    return test_res;
}

/*
 * Init
 */

static unsigned inited;
void sock_init(void)
{
    if (inited++) return;
    log_category_sock_init();
    mallocer_init();
    bench_init();
    ext_init();
    ext_param_bind_v6_as_v6_init();

    MALLOCER_INIT(sock_mallocer);

    udp_sym    = scm_permanent_object(scm_from_latin1_symbol("udp"));
    tcp_sym    = scm_permanent_object(scm_from_latin1_symbol("tcp"));
    ttcp_sym   = scm_permanent_object(scm_from_latin1_symbol("threaded-tcp"));
    unix_sym   = scm_permanent_object(scm_from_latin1_symbol("unix"));
    file_sym   = scm_permanent_object(scm_from_latin1_symbol("file"));
    buf_sym    = scm_permanent_object(scm_from_latin1_symbol("buffered"));
    client_sym = scm_permanent_object(scm_from_latin1_symbol("client"));
    server_sym = scm_permanent_object(scm_from_latin1_symbol("server"));

    sock_smob_init();
    ip_addr_ctor_from_str_any(&local_ip, "127.0.0.1");

    ext_function_ctor(&sg_make_sock,
        "make-sock", 2, 3, 0, g_make_sock,
        "(make-sock 'udp 'client \"some.host.com\" 5431): Connect to this host, port 5431, with default bufsize\n"
        "(make-sock 'udp 'server 5431): receive messages on this port\n"
        "(make-sock 'udp 'server 5431 300000): receive messages on this port with rcv buf size of 300kb\n"
        "(make-sock 'unix 'client \"/tmp/socket.file\" [max-file-size]): to use UNIX domain sockets\n"
        "(make-sock 'file 'client \"/tmp/msg_dir\" [max-file-size]): to convey messages through files\n"
        "(make-sock 'buffered 1024 other-sock)\n"
        "See also: sock-send, sock-recv");

    ext_function_ctor(&sg_sock_is_opened,
        "sock-opened?", 1, 0, 0, g_sock_is_opened,
        "(sock-opened? some-sock): Returns #t/#f depending on the state of the socket\n"
        "See also: make-sock");

    // these are intended for testing
    ext_function_ctor(&sg_sock_send,
        "sock-send", 2, 0, 0, g_sock_send,
        "(sock-send sock \"hello\"): Send this string through the sock object\n"
        "Return #t if the operation is successful\n"
        "See also: sock-recv, make-sock\n");
    ext_function_ctor(&sg_sock_recv,
        "sock-recv", 1, 0, 0, g_sock_recv,
        "(sock-recv sock): return the available list of messages (as strings)\n"
        "Will return #f on errors\n"
        "See also: sock-send, make-sock\n");
}

void sock_fini(void)
{
    if (--inited) return;

    // Cancel all our threads

    ext_param_bind_v6_as_v6_fini();
    log_category_sock_fini();

    mallocer_fini();
    ext_fini();
    bench_fini();
}
