// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef RTP_H_100520
#define RTP_H_100520
#include <junkie/proto/proto.h>
#include <junkie/tools/ip_addr.h>

/** @file
 * @brief RTP informations
 */

extern struct proto *proto_rtp;

struct rtp_proto_info {
    struct proto_info info;
    uint32_t sync_src;
    uint16_t seq_num;
    uint8_t payload_type;
    uint32_t timestamp;
};

char const *rtp_payload_type_2_str(uint8_t type);

void spawn_rtp_subparsers(struct ip_addr const *this_host, uint16_t this_port, struct ip_addr const *other_host, uint16_t other_port, struct timeval const *now, struct proto *requestor);

void rtp_init(void);
void rtp_fini(void);

#endif
