// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef SOCK_H_111028
#define SOCK_H_111028
#include <limits.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h> // for fd_set
#include <netinet/in.h>
#include <junkie/config.h>
#include <junkie/tools/ip_addr.h>
#include <junkie/tools/ext.h>

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
 *   messages survive the crash of the sender and receiver so that's more robust (but
 *   a restarting server will re-read some messages it already read in previous run).
 *   Also, we have an unlimited buffer (limited to disk size).
 *   Note: for files, the clients are the writers and the server the reader.
 *
 * For TCP and files, which are stream oriented, a header is prepended to each messages
 * to indicate their length.
 *
 * Along with these functions come guile wrappers to create named links between two hosts
 * (see (help "sock")).
 */

/// Generic type for sockets
struct sock {
    struct sock_ops {
        int (*send)(struct sock *, void const *, size_t);
        ssize_t (*recv)(struct sock *, void *, size_t, struct ip_addr *sender, int);    // sender will be set to 127.0.0.1 for UNIX domain/files sockets
        int (*set_fd)(struct sock *, fd_set *);  ///< add all selectable fds in this set, return the max
        int (*is_set)(struct sock *, fd_set const *);  ///< tells if (one of) the fd on which we receive message is set. the returned value is passed to recv.
        bool (*is_opened)(struct sock *);   ///< tells if a future send/recv is expected to work (useful to take any kind of action like reconnect)
        void (*del)(struct sock *);
    } const *ops;
    char name[64];
};

// Constructors

struct sock *sock_tcp_client_new(char const *host, char const *service, size_t buf_size);
struct sock *sock_tcp_server_new(char const *service, size_t buf_size);

struct sock *sock_udp_client_new(char const *host, char const *service, size_t buf_size);
struct sock *sock_udp_server_new(char const *service, size_t buf_size);

struct sock *sock_unix_client_new(char const *file);
struct sock *sock_unix_server_new(char const *file);

struct sock *sock_file_client_new(char const *file, off_t max_file_size);
struct sock *sock_file_server_new(char const *file, off_t max_file_size);

struct sock *scm_to_sock(SCM);

/** Sometime we want to buffer app msgs into a single net msg to minimize
 * syscalls or context switches.  (only when lag is not as issue).
 * Note that, due to the various sock ctors buff_sock_ctor does not
 * init the underlying sock. You have to build it yourself.
 * Notice that the packet will be sent when it's at least half full. */
struct sock_buf {
    struct sock sock;   // a sock_buf is a sock
    struct sock *ll_sock;   // using this one
    size_t mtu; // max size of each msg
    size_t out_sz, in_sz; // what's already there
    size_t in_rcvd; // what was already returned to reader
    uint8_t *out, *in; // buffers
    struct ip_addr prev_sender; // we need to store the sender of the batch (set if have_prev_sender)
    bool have_prev_sender;
};

/// Create a sock_buf with the attached sock.
int sock_buf_ctor(struct sock_buf *, size_t mtu, struct sock *);

/** Deletes the sock_buf (but *not* the attached sock).
 * Also, the buffer will be flushed before its lost. */
void sock_buf_dtor(struct sock_buf *);

// Init

void sock_init(void);
void sock_fini(void);

#endif
