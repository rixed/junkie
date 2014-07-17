// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef RPC_H_140717
#define RPC_H_140717

#include <junkie/proto/proto.h>

void rpc_init(void);
void rpc_fini(void);

extern struct proto *proto_rpc;

enum msg_type {
    RPC_CALL,
    RPC_REPLY
};

enum auth_flavor {
    RPC_AUTH_NULL,
    RPC_AUTH_UNIX,
    RPC_AUTH_SHORT,
    RPC_AUTH_DES,
} ;

enum reply_status {
    RPC_MSG_ACCEPTED,
    RPC_MSG_DENIED,
};

enum rejected_status {
    RPC_RPC_MISMATCH,
    RPC_AUTH_ERROR,
};

struct call_msg {
    uint32_t rpc_version;
    uint32_t program;
    uint32_t program_version;
    uint32_t procedure;
} ;

struct reply_msg {
    enum reply_status reply_status;
    // TODO parse rpc reply
};

struct rpc_proto_info {
    struct proto_info info;
    enum msg_type  msg_type;
    union {
        struct call_msg  call_msg;
        struct reply_msg reply_msg;
    } u;
};

#endif
