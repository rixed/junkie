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
    unsigned psh:1;
    unsigned urg:1;
    unsigned to_srv:1; // key.port[srv] is the server, aka set if the packet is going to the server
    uint16_t window;
    uint16_t urg_ptr;    // copied whatever the value of the urg flag
    uint32_t ack_num;
    uint32_t seq_num;
    uint32_t rel_seq_num;   // relative to ISN
    // Options
#   define TCP_MSS_SET 0x01 // Maximum Segment Size
#   define TCP_WSF_SET 0x02 // Window Size Scaling
    unsigned set_values;
    uint16_t mss;
    uint8_t wsf;
    uint8_t nb_options;
    uint8_t options[16]; // The option kind that were set, in order of appearance (useful for OS detection)
};

// You can use src = 0 or dst = 0 for any port
struct mux_subparser *tcp_subparser_and_parser_new(struct parser *parser, struct proto *proto,
        struct proto *requestor, uint16_t src, uint16_t dst, unsigned way, struct timeval const *now,
        struct mutex **mutex);

extern struct port_muxer_list tcp_port_muxers;

int tcp_seqnum_cmp(uint32_t, uint32_t);

void tcp_init(void);
void tcp_fini(void);

#endif
