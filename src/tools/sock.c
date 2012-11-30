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
#include "junkie/tools/objalloc.h"
#include "junkie/tools/ext.h"
#include "junkie/tools/mallocer.h"
#include "junkie/tools/serialization.h"

#undef LOG_CAT
#define LOG_CAT sock_log_category
LOG_CATEGORY_DEF(sock);

static struct ip_addr local_ip;

/*
 * Functions on socks
 */

static void sock_ctor(struct sock *s, struct sock_ops const *ops)
{
    SLOG(LOG_DEBUG, "Construct sock@%p", s);
    s->ops = ops;
}

static void sock_dtor(struct sock *s)
{
    SLOG(LOG_DEBUG, "Destruct sock %s", s->name);
}

/*
 * UDP sockets
 */

struct sock_udp {
    struct sock sock;
    int fd;
};

static int sock_udp_send(struct sock *s_, void const *buf, size_t len)
{
    struct sock_udp *s = DOWNCAST(s_, sock, sock_udp);

    SLOG(LOG_DEBUG, "Sending %zu bytes to %s (fd %d)", len, s->sock.name, s->fd);

    if (-1 == send(s->fd, buf, len, MSG_DONTWAIT)) {
        TIMED_SLOG(LOG_ERR, "Cannot send %zu bytes into %s: %s", len, s->sock.name, strerror(errno));
        return -1;
    }
    return 0;
}

static ssize_t sock_udp_recv(struct sock *s_, void *buf, size_t maxlen, struct ip_addr *sender)
{
    struct sock_udp *s = DOWNCAST(s_, sock, sock_udp);

    SLOG(LOG_DEBUG, "Reading on socket %s (fd %d)", s->sock.name, s->fd);

    union {
        struct sockaddr a;
        struct sockaddr_in ip4;
        struct sockaddr_in6 ip6;
        struct sockaddr_un unix;
    } src_addr;
    socklen_t addrlen = sizeof(src_addr);
    ssize_t r = recvfrom(s->fd, buf, maxlen, 0, &src_addr.a, &addrlen);
    if (r < 0) {
        TIMED_SLOG(LOG_ERR, "Cannot receive datagram from %s: %s", s->sock.name, strerror(errno));
    }
    if (sender) {
        if (addrlen > sizeof(src_addr)) {
            SLOG(LOG_ERR, "Cannot set sender address: size too big (%zu > %zu)", (size_t)addrlen, sizeof(src_addr));
            *sender = local_ip;
        } else {
            if (0 != ip_addr_ctor_from_sockaddr(sender, &src_addr.a, addrlen)) {
                *sender = local_ip;
            }
        }
    }

    SLOG(LOG_DEBUG, "read %zd bytes from %s out of %s", r, sender ? ip_addr_2_str(sender) : "unknown", s->sock.name);
    return r;
}

static int sock_udp_set_fd(struct sock *s_, fd_set *set)
{
    struct sock_udp *s = DOWNCAST(s_, sock, sock_udp);
    FD_SET(s->fd, set);
    return s->fd;
}

static bool sock_udp_is_set(struct sock *s_, fd_set const *set)
{
    struct sock_udp *s = DOWNCAST(s_, sock, sock_udp);
    return FD_ISSET(s->fd, set);
}

static void sock_udp_dtor(struct sock_udp *s)
{
    sock_dtor(&s->sock);
    file_close(s->fd);
}

static void sock_udp_del(struct sock *s_)
{
    struct sock_udp *s = DOWNCAST(s_, sock, sock_udp);
    sock_udp_dtor(s);
    objfree(s);
}

static struct sock_ops sock_udp_ops = {
    .send = sock_udp_send,
    .recv = sock_udp_recv,
    .set_fd = sock_udp_set_fd,
    .is_set = sock_udp_is_set,
    .del = sock_udp_del,
};

static int sock_udp_client_ctor(struct sock_udp *s, char const *host, char const *service, size_t buf_size)
{
    int res = -1;
    SLOG(LOG_DEBUG, "Construct sock to udp://%s:%s", host, service);

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

    struct sockaddr srv_addr;
    socklen_t srv_addrlen;
    int srv_family;

    for (struct addrinfo *info_ = info; info_; info_ = info_->ai_next) {
        memset(&srv_addr, 0, sizeof(srv_addr));
        memcpy(&srv_addr, info_->ai_addr, info_->ai_addrlen);
        srv_addrlen = info_->ai_addrlen;
        srv_family = info_->ai_family;

        char addr[256], srv[256];
        err = getnameinfo(&srv_addr, srv_addrlen, addr, sizeof(addr), srv, sizeof(srv), NI_DGRAM|NI_NOFQDN|NI_NUMERICSERV|NI_NUMERICHOST);
        if (! err) {
            snprintf(s->sock.name, sizeof(s->sock.name), "udp://%s@%s:%s", info->ai_canonname, addr, srv);
        } else {
            SLOG(LOG_WARNING, "Cannot getnameinfo(): %s", gai_strerror(err));
            snprintf(s->sock.name, sizeof(s->sock.name), "udp://%s@?:%s", info->ai_canonname, service);
        }
        SLOG(LOG_DEBUG, "Trying to use socket %s", s->sock.name);

        s->fd = socket(srv_family, SOCK_DGRAM, 0);
        if (s->fd < 0) {
            SLOG(LOG_WARNING, "Cannot socket(): %s", strerror(errno));
            continue;
        }

        // try to connect
        if (0 != connect(s->fd, &srv_addr, srv_addrlen)) {
            SLOG(LOG_WARNING, "Cannot connect(): %s", strerror(errno));
            continue;
        }

        res = 0;
        sock_ctor(&s->sock, &sock_udp_ops);
        SLOG(LOG_INFO, "Connected to %s", s->sock.name);
        break;  // go with this one
    }

    if (buf_size) set_rcvbuf(s->fd, buf_size);

    freeaddrinfo(info);
    return res;
}

struct sock *sock_udp_client_new(char const *host, char const *service, size_t buf_size)
{
    struct sock_udp *s = objalloc(sizeof(*s), "udp sockets");
    if (! s) return NULL;
    if (0 != sock_udp_client_ctor(s, host, service, buf_size)) {
        objfree(s);
        return NULL;
    }
    return &s->sock;
}

static int sock_udp_server_ctor(struct sock_udp *s, char const *service, size_t buf_size)
{
    int res = -1;
    SLOG(LOG_DEBUG, "Construct sock for serving %s/udp", service);

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

    struct sockaddr srv_addr;
    socklen_t srv_addrlen;
    int srv_family;

    for (struct addrinfo *info_ = info; info_; info_ = info_->ai_next) {
        memset(&srv_addr, 0, sizeof(srv_addr));
        memcpy(&srv_addr, info_->ai_addr, info_->ai_addrlen);
        srv_addrlen = info_->ai_addrlen;
        srv_family = info_->ai_family;
        snprintf(s->sock.name, sizeof(s->sock.name), "udp://*.%s", service);

        s->fd = socket(srv_family, SOCK_DGRAM, 0);
        if (s->fd < 0) {
            SLOG(LOG_WARNING, "Cannot socket(): %s", strerror(errno));
            continue;
        }
        if (0 != bind(s->fd, &srv_addr, srv_addrlen)) {
            SLOG(LOG_WARNING, "Cannot bind(): %s", strerror(errno));
            (void)close(s->fd);
            s->fd = -1;
            continue;
        } else {
            res = 0;
            sock_ctor(&s->sock, &sock_udp_ops);
            SLOG(LOG_INFO, "Serving %s", s->sock.name);
            break;
        }
    }

    if (buf_size) set_rcvbuf(s->fd, buf_size);

    freeaddrinfo(info);
    return res;
}

struct sock *sock_udp_server_new(char const *service, size_t buf_size)
{
    struct sock_udp *s = objalloc(sizeof(*s), "udp sockets");
    if (! s) return NULL;
    if (0 != sock_udp_server_ctor(s, service, buf_size)) {
        objfree(s);
        return NULL;
    }
    return &s->sock;
}

/*
 * TCP sockets
 */

struct sock_tcp {
    struct sock sock;
    int listener_fd;
    // TODO: plus a list/array of clients
};

struct sock *sock_tcp_client_new(char const unused_ *host, char const unused_ *service, size_t unused_ buf_size)
{
    assert(!"TODO");
}

struct sock *sock_tcp_server_new(char const unused_ *service, size_t unused_ buf_size)
{
    assert(!"TODO");
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

    if (-1 == send(s->fd, buf, len, 0)) {
        TIMED_SLOG(LOG_ERR, "Cannot send %zu bytes into %s: %s", len, s->sock.name, strerror(errno));
        return -1;
    }
    return 0;
}

static ssize_t sock_unix_recv(struct sock *s_, void *buf, size_t maxlen, struct ip_addr *sender)
{
    struct sock_unix *s = DOWNCAST(s_, sock, sock_unix);

    SLOG(LOG_DEBUG, "Reading on socket %s (fd %d)", s->sock.name, s->fd);

    struct sockaddr src_addr;
    socklen_t addrlen = sizeof(src_addr);
    ssize_t r = recvfrom(s->fd, buf, maxlen, 0, &src_addr, &addrlen);
    if (r < 0) {
        TIMED_SLOG(LOG_ERR, "Cannot receive datagram from %s: %s", s->sock.name, strerror(errno));
    }
    if (sender) *sender = local_ip;

    SLOG(LOG_DEBUG, "read %zd bytes out of %s", r, s->sock.name);
    return r;
}

static int sock_unix_set_fd(struct sock *s_, fd_set *set)
{
    struct sock_unix *s = DOWNCAST(s_, sock, sock_unix);
    FD_SET(s->fd, set);
    return s->fd;
}

static bool sock_unix_is_set(struct sock *s_, fd_set const *set)
{
    struct sock_unix *s = DOWNCAST(s_, sock, sock_unix);
    return FD_ISSET(s->fd, set);
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
    objfree(s);
}

static struct sock_ops sock_unix_ops = {
    .send = sock_unix_send,
    .recv = sock_unix_recv,
    .set_fd = sock_unix_set_fd,
    .is_set = sock_unix_is_set,
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
        (void)close(s->fd);
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
    struct sock_unix *s = objalloc(sizeof(*s), "unix sockets");
    if (! s) return NULL;
    if (0 != sock_unix_client_ctor(s, file)) {
        objfree(s);
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
        (void)close(s->fd);
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
    struct sock_unix *s = objalloc(sizeof(*s), "unix sockets");
    if (! s) return NULL;
    if (0 != sock_unix_server_ctor(s, file)) {
        objfree(s);
        return NULL;
    }
    return &s->sock;
}

/*
 * File "sockets"
 */

typedef uint32_t file_msg_len;

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
    s->fd = file_open(path, (s->server ? O_RDONLY:O_WRONLY)|O_CREAT);
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

    file_msg_len msg_len = len;
    struct iovec iov[2] = {
        { .iov_base = &msg_len, .iov_len = sizeof(msg_len), },
        { .iov_base = (void *)buf, .iov_len = len, },
    };
    return file_writev(s->fd, iov, NB_ELEMS(iov));
}

static ssize_t sock_file_recv(struct sock *s_, void *buf, size_t maxlen, struct ip_addr *sender)
{
    struct sock_file *s = DOWNCAST(s_, sock, sock_file);

    SLOG(LOG_DEBUG, "Reading on socket %s (fd %d)", s->sock.name, s->fd);

    if (s->fd < 0 || (s->max_file_size > 0 && file_offset(s->fd) >= s->max_file_size)) {
        if (0 != sock_file_open(s, s->fd >= 0 ? s->id+1 : 0)) return -1;
    }

    file_msg_len len;
    ssize_t r = file_read(s->fd, &len, sizeof(len));
    if (r < 0) {
        SLOG(LOG_ERR, "Cannot read a message size from %s: skip file!", s->sock.name);
skip:
        file_close(s->fd);
        s->fd = -1;
        s->id ++;
        return -1;
    }

    if (len > maxlen) {
        SLOG(LOG_ERR, "Message size from %s (%zu) bigger than max expected message size (%zu), skip file!", s->sock.name, (size_t)len, maxlen);
        goto skip;
    }

    r = file_read(s->fd, buf, len);
    if (r < 0) {
        SLOG(LOG_ERR, "Cannot read a message of %zd bytes from %s: skip file!", (size_t)len, s->sock.name);
        goto skip;
    }

    if (sender) *sender = local_ip;

    SLOG(LOG_DEBUG, "read %zd bytes out of %s", r, s->sock.name);
    return r;
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

static bool sock_file_is_set(struct sock *s_, fd_set const *set)
{
    struct sock_file *s = DOWNCAST(s_, sock, sock_file);
    return s->fd >= 0 && FD_ISSET(s->fd, set);
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
    objfree(s);
}

static struct sock_ops sock_file_ops = {
    .send = sock_file_send,
    .recv = sock_file_recv,
    .set_fd = sock_file_set_fd,
    .is_set = sock_file_is_set,
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
    struct sock_file *s = objalloc(sizeof(*s), "file sockets");
    if (! s) return NULL;
    if (0 != sock_file_ctor(s, dir, max_file_size, false)) {
        objfree(s);
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
    struct sock_file *s = objalloc(sizeof(*s), "file sockets");
    if (! s) return NULL;
    if (0 != sock_file_server_ctor(s, dir, max_file_size)) {
        objfree(s);
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
    int ret = s->ll_sock->ops->send(s->ll_sock, s->out, s->out_sz);
    s->out_sz = 0;
    return ret;
}

static int sock_buf_send(struct sock *s_, void const *buf, size_t len)
{
    struct sock_buf *s = DOWNCAST(s_, sock, sock_buf);

    if (len >= s->mtu) {
        SLOG(LOG_ERR, "Can't buffer %zu bytes into MTU of %zu", len, s->mtu);
        return -1;
    }

    if (s->mtu + len + LEN_BYTES > s->mtu) (void)sock_buf_flush(s);

    uint8_t *ser_buf = s->out + s->out_sz;
    SERIALIZE(&ser_buf, len);
    memcpy(ser_buf, buf, len);

    s->out_sz += LEN_BYTES + len;

    if (s->out_sz <= s->mtu) return 0;

    return sock_buf_flush(s);
}

static ssize_t sock_buf_recv(struct sock *s_, void *buf, size_t maxlen, struct ip_addr *sender)
{
    struct sock_buf *s = DOWNCAST(s_, sock, sock_buf);

    SLOG(LOG_DEBUG, "Reading on socket %s", s->sock.name);

    ssize_t rem_len = s->in_sz - s->in_rcvd;
    if (rem_len > 0) {
        // We have a msg left in receive buffer
        if (rem_len < LEN_BYTES) {
            SLOG(LOG_ERR, "Received a trunced PDU?");
badmsg:     s->in_rcvd = s->in_sz = 0;
            return -1;
        }
        uint8_t const *ser_buf = s->in + s->in_rcvd;
        size_t len = DESERIALIZE(&ser_buf);
        if (len > (size_t)rem_len) {
            SLOG(LOG_ERR, "Received badly packed msg of %zu bytes in PDU of %zu bytes", len, s->in_sz);
            goto badmsg;
        }
        if (len > maxlen) {
            SLOG(LOG_ERR, "Received a msg of %zu bytes larger that incoming buffer (%zu)", len, maxlen);
            goto badmsg;
        }
        memcpy(buf, ser_buf, len);
        s->in_rcvd += LEN_BYTES + len;
        SLOG(LOG_DEBUG, "read %zd bytes out of %s", len, s->sock.name);
        return len;
    } else {
        // Receive buffer is empty
        s->in_rcvd = s->in_sz = 0;
        ssize_t ret = s->ll_sock->ops->recv(s->ll_sock, s->in, s->mtu, sender);
        if (ret <= 0) return ret;
        s->in_sz = ret;
        return sock_buf_recv(s_, buf, maxlen, sender);
    }
}

static int sock_buf_set_fd(struct sock *s_, fd_set *set)
{
    struct sock_buf *s = DOWNCAST(s_, sock, sock_buf);
    return s->ll_sock->ops->set_fd(s->ll_sock, set);
}

static bool sock_buf_is_set(struct sock *s_, fd_set const *set)
{
    struct sock_buf *s = DOWNCAST(s_, sock, sock_buf);
    // It's important to check ll_sock before received size because of its is_set side effects
    return s->ll_sock->ops->is_set(s->ll_sock, set) ||
           (s->in_sz > s->in_rcvd);
}

void sock_buf_dtor(struct sock_buf *s)
{
    sock_buf_flush(s);
    sock_dtor(&s->sock);
    FREE(s->in);
    FREE(s->out);
}

static void sock_buf_del(struct sock *s_)
{
    struct sock_buf *s = DOWNCAST(s_, sock, sock_buf);
    sock_buf_dtor(s);
    objfree(s);
}

static struct sock_ops sock_buf_ops = {
    .send = sock_buf_send,
    .recv = sock_buf_recv,
    .set_fd = sock_buf_set_fd,
    .is_set = sock_buf_is_set,
    .del = sock_buf_del,
};

int sock_buf_ctor(struct sock_buf *s, size_t mtu, struct sock *ll_sock)
{
    MALLOCER(sock_buffers);
    s->in = MALLOC(sock_buffers, mtu);
    if (! s->in) return -1;
    s->out = MALLOC(sock_buffers, mtu);
    if (! s->out) {
        FREE(s->in);
        return -1;
    }

    sock_ctor(&s->sock, &sock_buf_ops);
    snprintf(s->sock.name, sizeof(s->sock.name), "%s (buf up to %zu)", ll_sock->name, mtu);

    s->mtu = mtu;
    s->ll_sock = ll_sock;
    s->out_sz = s->in_sz = s->in_rcvd = 0;

    return 0;
}

struct sock *sock_buf_new(size_t mtu, struct sock *ll_sock)
{
    struct sock_buf *s = objalloc(sizeof(*s), "sockets");
    if (! s) return NULL;
    if (0 != sock_buf_ctor(s, mtu, ll_sock)) {
        objfree(s);
        return NULL;
    }
    return &s->sock;
}


/*
 * The Sock Smob
 */

static scm_t_bits sock_smob_tag;
static SCM udp_sym;
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

static struct ext_function sg_sock_recv;
static SCM g_sock_recv(SCM sock_)
{
    scm_assert_smob_type(sock_smob_tag, sock_);
    struct sock *sock = (struct sock *)SCM_SMOB_DATA(sock_);

    char buf[1024]; // Receiving from guile is for testing purpose only!
    ssize_t len = sock->ops->recv(sock, buf, sizeof(buf), NULL);
    if (len < 0) return SCM_BOOL_F;

    return scm_from_latin1_stringn(buf, len);
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
    ext_init();

    udp_sym    = scm_permanent_object(scm_from_latin1_symbol("udp"));
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

    // these are intended for testing
    ext_function_ctor(&sg_sock_send,
        "sock-send", 2, 0, 0, g_sock_send,
        "(sock-send sock \"hello\"): Send this string through the sock object\n"
        "Return #t if the operation is successful\n"
        "See also: sock-recv, make-sock\n");
    ext_function_ctor(&sg_sock_recv,
        "sock-recv", 1, 0, 0, g_sock_recv,
        "(sock-recv sock): wait until a message is received and return it as a string\n"
        "Will return #f on errors\n"
        "See also: sock-send, make-sock\n");
}

void sock_fini(void)
{
    if (--inited) return;

    log_category_sock_fini();
    mallocer_fini();
    ext_fini();
}
