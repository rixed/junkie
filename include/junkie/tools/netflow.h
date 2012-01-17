// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef NETFLOW_H_120117
#define NETFLOW_H_120117
#include <stdint.h>

/** @file
 * @brief Tools to encode/decode netflow messages
 */

struct nf_flow {
    // all [2] are source then dest
    struct ip_addr addr[2];
    struct ip_addr next_hop;
    uint16_t port[2];
    uint_least32_t in_iface, out_iface;
    uint_least32_t packets;
    uint_least32_t bytes;
    uint_least32_t first_ts, last_ts;
    unsigned tcp_flags;
    unsigned ip_proto, ip_tos;
    unsigned as[2];
    unsigned mask[2];
};

struct nf_msg {
    unsigned version;
    unsigned nb_flows;
    unsigned sys_uptime;
    struct timeval ts;
    unsigned seqnum;
    unsigned engine_type, engine_id;
    enum { NONE } sampling_mode;
    unsigned sample_rate;
#   define MAX_NF_FLOWS 1024
    struct nf_flow flows[MAX_NF_FLOWS];
};

/** Decode a netflow message */
// @return number of bytes read, of -1 on error.
ssize_t netflow_decode_msg(struct nf_msg *, void const *src, size_t size);

/** Start a listener on this port and call the given function for each flow */
// @note stops as soon as the callback returns any negative value.
int netflow_listen(char const *service, int (*cb)(struct nf_msg const *, struct nf_flow const *));

void netflow_init(void);
void netflow_fini(void);

#endif
