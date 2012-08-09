// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef SOCK_H_111028
#define SOCK_H_111028
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <junkie/config.h>
#include <junkie/tools/ip_addr.h>

/** @file
 * @brief Tools to send/receive message via all kind of sockets
 *
 * You can choose between UDP/TCP/Unix domain/files, each one having it's
 * pro and cons:
 *
 * - UDP is simple, fast and bidirectional, but some msgs can be dropped, even locally
 * - TCP guarantees delivery but is slower than UDP
 * - UNIX local domain is faster and reliable, but is local only.
 *   Additionally, it will synchronise sender and receiver, which is a feature or not
 * - Files are local only and unidirectional. Also, it's the slowest method, but
 *   messages survive the crash of the sender and receiver so that's more robust.
 *   Note: for files, the client is the writer and the server the reader.
 *
 * For TCP and files, which are stream oriented, a header is prepended to each messages
 * to indicate their length.
 *
 * Along with these functions come guile wrappers to create named links between two hosts:
 *
 * (connect-udp "the.host.com" 4323)
 * (listen-udp 4324)
 * (connect-unix "/tmp/mysocket")
 * and so on, returning a struct object.
 */

/// Generic type for sockets
struct sock {
    struct sock_ops {
        int (*send)(struct sock *, void const *, size_t);
        ssize_t (*recv)(struct sock *, void *, size_t, struct ip_addr *sender);    // sender will be set to 127.0.0.1 for UNIX domain/files sockets
        void (*del)(struct sock *);
    } const *ops;
    int fd;
    char name[64];
};

// Constructors

struct sock *sock_tcp_client_new(char const *host, char const *service);
struct sock *sock_tcp_server_new(char const *service);

struct sock *sock_udp_client_new(char const *host, char const *service);
struct sock *sock_udp_server_new(char const *service);

struct sock *sock_unix_client_new(char const *file);
struct sock *sock_unix_server_new(char const *file);

struct sock *sock_file_client_new(char const *file);
struct sock *sock_file_server_new(char const *file);

// Misc

bool sock_is_opened(struct sock *s);

// Init

void sock_init(void);
void sock_fini(void);

#endif
