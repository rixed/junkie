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
#include "junkie/tools/objalloc.h"
#include "junkie/tools/ext.h"

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

    struct sockaddr src_addr;
    socklen_t addrlen = sizeof(src_addr);
    ssize_t r = recvfrom(s->fd, buf, maxlen, 0, &src_addr, &addrlen);
    if (r < 0) {
        TIMED_SLOG(LOG_ERR, "Cannot receive datagram from %s: %s", s->sock.name, strerror(errno));
    }
    if (sender) {
        if (addrlen > sizeof(src_addr)) {
            SLOG(LOG_ERR, "Cannot set sender address: size too big (%zu > %zu)", (size_t)addrlen, sizeof(src_addr));
            *sender = local_ip;
        } else {
            if (0 != ip_addr_ctor_from_sockaddr(sender, &src_addr, addrlen)) {
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

static int sock_udp_client_ctor(struct sock_udp *s, char const *host, char const *service)
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
            snprintf(s->sock.name, sizeof(s->sock.name), "udp://%s@%s.%s", info->ai_canonname, addr, srv);
        } else {
            SLOG(LOG_WARNING, "Cannot getnameinfo(): %s", gai_strerror(err));
            snprintf(s->sock.name, sizeof(s->sock.name), "udp://%s@?.%s", info->ai_canonname, service);
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

    freeaddrinfo(info);
    return res;
}

struct sock *sock_udp_client_new(char const *host, char const *service)
{
    struct sock_udp *s = objalloc(sizeof(*s), "udp sockets");
    if (! s) return NULL;
    if (0 != sock_udp_client_ctor(s, host, service)) {
        objfree(s);
        return NULL;
    }
    return &s->sock;
}

static int sock_udp_server_ctor(struct sock_udp *s, char const *service)
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

    freeaddrinfo(info);
    return res;
}

struct sock *sock_udp_server_new(char const *service)
{
    struct sock_udp *s = objalloc(sizeof(*s), "udp sockets");
    if (! s) return NULL;
    if (0 != sock_udp_server_ctor(s, service)) {
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

struct sock *sock_tcp_client_new(char const unused_ *host, char const unused_ *service)
{
    assert(!"TODO");
}

struct sock *sock_tcp_server_new(char const unused_ *service)
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
    (void)file_unlink(s->file);
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

struct sock_file {
    struct sock sock;
    char dir[PATH_MAX];
    size_t max_file_size;
    // TODO: last fd
};

struct sock * sock_file_client_new(char const unused_ *file)
{
    assert(!"TODO");
}

struct sock * sock_file_server_new(char const unused_ *file)
{
    assert(!"TODO");
}

/*
 * The Sock Smob
 */

static scm_t_bits sock_smob_tag;
static SCM udp_sym;
static SCM unix_sym;
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

// Caller must have started a scm-dynwind region
static struct sock *make_sock_udp(SCM p1_, SCM p2_)
{
    if (SCM_UNBNDP(p1_)) {
        scm_throw(scm_from_latin1_symbol("missing-argument"),
                  scm_list_1(scm_from_latin1_symbol("host")));
    }

    struct sock *s = NULL;

    char *p1 = scm_to_locale_string(p1_);
    scm_dynwind_free(p1);

    if (SCM_BNDP(p2_)) {
        // when host+service are given, we are a client
        char *service = scm_to_locale_string(p2_);
        scm_dynwind_free(service);
        s = sock_udp_client_new(p1, service);
    } else {
        // when only service is given, we are a server
        s = sock_udp_server_new(p1);
    }

    if (! s) {
        scm_throw(scm_from_latin1_symbol("cannot-create-udp-sock"),
                  SCM_EOL);
    }

    return s;
}

// Caller must have started a scm-dynwind region
static struct sock *make_sock_unix(SCM p1_, SCM p2_)
{
    if (SCM_UNBNDP(p1_)) {
miss_file:
        scm_throw(scm_from_latin1_symbol("missing-argument"),
                  scm_list_1(scm_from_latin1_symbol("file")));
    }

    SCM file_ = p1_;
    SCM type_ = p2_;
    if (! scm_is_string(file_)) {
        file_ = p2_;
        type_ = p1_;
        if (SCM_UNBNDP(file_) || !scm_is_string(file_)) {
            goto miss_file;
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
        scm_throw(scm_from_latin1_symbol("cannot-create-unix-sock"),
                  SCM_EOL);
    }

    return s;
}

static struct ext_function sg_make_sock;
static SCM g_make_sock(SCM type, SCM p1, SCM p2)
{
    scm_dynwind_begin(0);
    struct sock *s = NULL;
    if (scm_is_eq(type, udp_sym)) {
        s = make_sock_udp(p1, p2);
    } else if (scm_is_eq(type, unix_sym)) {
        s = make_sock_unix(p1, p2);
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

/*
 * Init
 */

static unsigned inited;
void sock_init(void)
{
    if (inited++) return;
    log_category_sock_init();
    ext_init();

    udp_sym    = scm_permanent_object(scm_from_latin1_symbol("udp"));
    unix_sym   = scm_permanent_object(scm_from_latin1_symbol("unix"));
    client_sym = scm_permanent_object(scm_from_latin1_symbol("client"));
    server_sym = scm_permanent_object(scm_from_latin1_symbol("server"));

    sock_smob_init();
    ip_addr_ctor_from_str_any(&local_ip, "127.0.0.1");

    ext_function_ctor(&sg_make_sock,
        "make-sock", 2, 1, 0, g_make_sock,
        "(make-sock 'udp \"some.host.com\" 5431): Connect to this host\n"
        "(make-sock 'udp 5431): receive messages on this port\n"
        "(make-sock 'unix 'client \"/tmp/socket.file\"): to use UNIX domain sockets\n");
}

void sock_fini(void)
{
    if (--inited) return;

    log_category_sock_fini();
    ext_fini();
}
