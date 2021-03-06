// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef LIB_H_100427
#define LIB_H_100427
#include <junkie/proto/proto.h>

void stress_check(struct proto *proto);

int iph_ctor(void *ip, size_t len, uint32_t src, uint32_t dst);
int udph_ctor(void *udp, size_t len, uint16_t src, uint16_t dst);
int udp_ctor_random(void *packet, size_t len);

int tcph_ctor(void *tcp, size_t len, uint16_t src, uint16_t dst, uint32_t seqnum, uint32_t acknum, bool syn, bool fin, bool rst, bool ack);
int tcp_ctor_random(void *packet, size_t len);

struct tcp_stream {
    size_t past_len[2];
    size_t len;
    uint32_t isn[2];
    size_t mtu;
    uint32_t ip[2];
    uint16_t port[2];
    bool fin_acked[2];  // true if this way's FIN was acked
    uint8_t *packet;
};

int tcp_stream_ctor(struct tcp_stream *stream, size_t len, size_t mtu, uint16_t service_port);
void tcp_stream_dtor(struct tcp_stream *stream);

// Returns the size of the generated packet, or 0 if finished, -1 on errors
ssize_t tcp_stream_next(struct tcp_stream *stream, unsigned *way);

#endif
