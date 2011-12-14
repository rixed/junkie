// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef TCP_H_100402
#define TCP_H_100402
#include <junkie/proto/proto.h>
#include <junkie/proto/port_muxer.h>
#include <junkie/cpp.h>

/** @file
 * @brief TCP informations
 */

extern struct proto *proto_tcp;

struct tcp_proto_info {
    struct proto_info info;
    struct port_key key;
    unsigned syn:1;
    unsigned ack:1;
    unsigned rst:1;
    unsigned fin:1;
    uint16_t window;
    uint32_t ack_num;
    uint32_t seq_num;
};

// You can use src = 0 or dst = 0 for any port
struct mux_subparser *tcp_subparser_and_parser_new(struct parser *parser, struct proto *proto, struct proto *requestor, uint16_t src, uint16_t dst, unsigned way, struct timeval const *now);
struct mux_subparser *tcp_subparser_lookup(struct parser *parser, struct proto *proto, struct proto *requestor, uint16_t src, uint16_t dst, unsigned way, struct timeval const *now);

extern struct port_muxer_list tcp_port_muxers;

void tcp_init(void);
void tcp_fini(void);

#endif
