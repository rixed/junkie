// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef UDP_H_100402
#define UDP_H_100402
#include <junkie/proto/proto.h>
#include <junkie/proto/port_muxer.h>
#include <junkie/cpp.h>

/** @file
 * @brief UDP informations
 */

extern struct proto *proto_udp;

struct udp_proto_info {
    struct proto_info info;
    struct port_key key;
};

// TODO: inline them ?
struct mux_subparser *udp_subparser_and_parser_new(struct parser *parser, struct proto *proto, struct proto *requestor, uint16_t src, uint16_t dst, unsigned way, struct timeval const *now);

extern struct port_muxer_list udp_port_muxers;

void udp_init(void);
void udp_fini(void);

#endif
