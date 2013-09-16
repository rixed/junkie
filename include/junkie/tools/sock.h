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
#include <junkie/tools/bench.h>

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
 * Beware that writing in most of these socks is not thread safe.
 *
 * Along with these functions come guile wrappers to create named links between two hosts
 * (see (help "sock")).
 */

#define SOCK_MAX_MSG_SIZE 20000

struct sock;

/// The callback function on reception
typedef int sock_receiver(struct sock *, size_t, uint8_t const *, struct ip_addr const *sender);

/// Generic type for sockets
struct sock {
    struct sock_ops {
        int (*send)(struct sock *, void const *, size_t);
        /// sender will be set to 127.0.0.1 for UNIX domain/files sockets.
        int (*recv)(struct sock *, fd_set *);
        /// add all selectable fds in this set, return the max
        int (*set_fd)(struct sock *, fd_set *);
        /// tells if a future send/recv is expected to work (useful to take any kind of action like reconnect)
        bool (*is_opened)(struct sock *);
        void (*del)(struct sock *);
    } const *ops;
    char name[64];
    sock_receiver *receiver;    // Set this before calling recv!
    void *user_data;            // whatever extension you want
    struct bench_event sending;
};

// Constructors

struct sock *sock_tcp_client_new(char const *host, char const *service, size_t buf_size);
struct sock *sock_tcp_server_new(char const *service, size_t buf_size, bool threaded);

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
    size_t out_sz; // what's already there waiting to be sent
    uint8_t *out; // buffer
};

/// Create a sock_buf with the attached sock.
int sock_buf_ctor(struct sock_buf *, size_t mtu, struct sock *);

/** Deletes the sock_buf (but *not* the attached sock).
 * Also, the buffer will be flushed before its lost. */
void sock_buf_dtor(struct sock_buf *);

/// Simple select for single sock. the fd_set is an output parameter
int sock_select_single(struct sock *, fd_set *);

// Init

void sock_init(void);
void sock_fini(void);

#endif
