// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2010, SecurActive.
 *
 * This file is part of Junkie.
 *
 * Junkie is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Junkie is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Junkie.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdlib.h>
#include <arpa/inet.h>  // for ntohs()
#include "junkie/tools/log.h"
#include "junkie/tools/ip_addr.h"
#include "junkie/cpp.h"
#include "junkie/tools/netflow.h"

#undef LOG_CAT
#define LOG_CAT netflow_log_category
LOG_CATEGORY_DEF(netflow);

struct nf_msg_ll {
    uint16_t version;
    uint16_t nb_flows;
    uint32_t sys_uptime;
    uint32_t ts_sec;
    uint32_t ts_nsec;
    uint32_t seqnum;
    uint8_t engine_type;
    uint8_t engine_id;
    uint16_t sampling;
} packed_;

struct nf_flow_ll {
    uint32_t addr[2];
    uint32_t next_hop;
    uint16_t in_iface, out_iface;
    uint32_t packets;
    uint32_t bytes;
    uint32_t first_ts;
    uint32_t last_ts;
    uint16_t port[2];
    uint8_t padding;
    uint8_t tcp_flags;
    uint8_t ip_proto;
    uint8_t ip_tos;
    uint16_t as[2];
    uint8_t mask[2];
    uint16_t padding2;
} packed_;

#define CONV_IP(s, x) ip_addr_ctor_from_ip4(&s->x, s##_ll->x)
#define CONV_16(s, x) s->x = ntohs(s##_ll->x)
#define CONV_32(s, x) s->x = ntohl(s##_ll->x)
#define CONV_8(s, x)  s->x = s##_ll->x

// Decode the flow in src into flow. We already checked there are enough bytes to read in src.
static int nf_flow_decode(struct nf_flow *flow, void const *src)
{
    struct nf_flow_ll const *flow_ll = src; // FIXME: won't work if not properly aligned

    CONV_IP(flow, addr[0]);   CONV_IP(flow, addr[1]);    CONV_IP(flow, next_hop);
    CONV_16(flow, port[0]);   CONV_16(flow, port[1]);
    CONV_16(flow, in_iface);  CONV_16(flow, out_iface);
    CONV_32(flow, packets);   CONV_32(flow, bytes);
    CONV_32(flow, first_ts);  CONV_32(flow, last_ts);
    CONV_8(flow, tcp_flags);  CONV_8(flow, ip_proto);    CONV_8(flow, ip_tos);
    CONV_16(flow, as[0]);     CONV_16(flow, as[1]);
    CONV_8(flow, mask[0]);    CONV_8(flow, mask[1]);

    return 0;
}

// the caller must have checked there are
static int nf_msg_head_decode(struct nf_msg *msg, void const *src)
{
    struct nf_msg_ll const *msg_ll = src;   // FIXME: won't work if not properly aligned

    CONV_16(msg, version);
    CONV_16(msg, nb_flows);
    CONV_32(msg, sys_uptime);
    msg->ts.tv_sec  = ntohl(msg_ll->ts_sec);
    msg->ts.tv_usec = 1000 * ntohl(msg_ll->ts_nsec);
    CONV_32(msg, seqnum);
    CONV_8(msg, engine_type);
    CONV_8(msg, engine_id);
    uint16_t sampling = ntohs(msg_ll->sampling);
    msg->sampling_mode = sampling >> 14U;
    msg->sample_rate = sampling & 0x2FFF;

    return 0;
}

ssize_t netflow_decode_msg(struct nf_msg *msg, void const *src, size_t size)
{
    if (size < sizeof(struct nf_msg_ll)) {
        SLOG(LOG_INFO, "Cannot decode netflow msg: too few bytes (%zu < %zu)", size, sizeof(struct nf_msg_ll));
        return -1;
    }

    uint8_t const *ptr = src;
    if (0 != nf_msg_head_decode(msg, ptr)) return -1;
    ptr += sizeof(struct nf_msg_ll);

    size_t const tot_size = sizeof(struct nf_msg_ll) + msg->nb_flows * sizeof(struct nf_flow_ll);
    if (size < tot_size) {
        SLOG(LOG_INFO, "Cannot decode netflow msg: too few bytes (%zu < %zu)", size, tot_size);
        return -1;
    }

    for (unsigned f = 0; f < msg->nb_flows; f++) {
        if (0 != nf_flow_decode(msg->flows+f, ptr)) return -1;
        ptr += sizeof(struct nf_flow_ll);
    }

    return tot_size;
}

/*
 * Init
 */

static unsigned inited;
void netflow_init(void)
{
    if (inited++) return;
    log_category_netflow_init();
}

void netflow_fini(void)
{
    if (--inited) return;

    log_category_netflow_fini();
}

