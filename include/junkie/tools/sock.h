// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef SOCK_H_111028
#define SOCK_H_111028
#include <sys/types.h>
#include <sys/socket.h>
#include <junkie/config.h>
#include <junkie/tools/ip_addr.h>

/** @file
 * @brief Tools to send/receive message via sockets
 */

struct sock {
    int fd;
    struct sockaddr srv_addr;
    size_t srv_addrlen;
    int srv_family;
    char name[64];
};

int sock_ctor_client(struct sock *, char const *host, char const *service);
int sock_ctor_server(struct sock *, char const *service);
void sock_dtor(struct sock *);
int sock_send(struct sock *, void const *, size_t);
ssize_t sock_recv(struct sock *, void *, size_t, struct ip_addr *sender);
bool sock_is_opened(struct sock *);

void sock_init(void);
void sock_fini(void);

#endif
