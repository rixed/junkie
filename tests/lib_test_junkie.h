// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef LIB_H_100427
#define LIB_H_100427
#include <junkie/proto/proto.h>
#include <junkie/proto/ip.h>

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

#define VALUES_ARE_SET(proto, x) ((proto->set_values & (x)) == (x))

int check_big_int(uint64_t value, uint64_t expected, char const *field);
#define CHECK_BIG_INT(VAL, EXP) assert(0 == check_big_int(VAL, EXP, #VAL))

int check_int(uint32_t value, uint32_t expected, char const *field);
#define CHECK_INT(VAL, EXP) assert(0 == check_int(VAL, EXP, #VAL))

int check_str(char const *value, char const *expected, char const *field);
#define CHECK_STR(VAL, EXP) assert(0 == check_str(VAL, EXP, #VAL))

int check_set_values(unsigned value, unsigned expected, unsigned mask, char const *mask_name);
#define CHECK_SET_VALUE(INFO, EXPECTED, MASK) assert(0 == check_set_values(INFO->set_values, EXPECTED->set_values, MASK, #MASK))

void compare_proto_info(struct proto_info const *const info, struct proto_info const *const expected);
void compare_ip_proto_info(struct ip_proto_info const *const info, struct ip_proto_info const *const expected);

void set_debug_log(void);

#endif
