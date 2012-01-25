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
#include <inttypes.h>
#include <arpa/inet.h>  // for ntohs()
#include "junkie/cpp.h"
#include "junkie/tools/log.h"
#include "junkie/tools/ip_addr.h"
#include "junkie/tools/timeval.h"
#include "junkie/tools/netflow.h"
#include "junkie/tools/sock.h"

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
    uint32_t first; // sysuptime at the first packet
    uint32_t last;  // sysuptime at the last packet
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
static int nf_flow_decode(struct nf_flow *flow, struct nf_msg const *head, void const *src)
{
    struct nf_flow_ll const *flow_ll = src; // FIXME: won't work if not properly aligned

    CONV_IP(flow, addr[0]);   CONV_IP(flow, addr[1]);    CONV_IP(flow, next_hop);
    CONV_16(flow, port[0]);   CONV_16(flow, port[1]);
    CONV_16(flow, in_iface);  CONV_16(flow, out_iface);
    CONV_32(flow, packets);   CONV_32(flow, bytes);
    CONV_8(flow, tcp_flags);  CONV_8(flow, ip_proto);    CONV_8(flow, ip_tos);
    CONV_16(flow, as[0]);     CONV_16(flow, as[1]);
    CONV_8(flow, mask[0]);    CONV_8(flow, mask[1]);
    /* The first/last fields of the netflow are the uptime at the first/last pkt of the flow.
     * We find a timestamp more interesting, so we get it from sysuptime and localtime of the header.
     * But this imply trusting the netflow header localtime. */
    SLOG(LOG_DEBUG, "Decoding a flow which sys_uptime=%"PRIu32", now=%s, first=%u, last=%u",
        head->sys_uptime, timeval_2_str(&head->ts), ntohl(flow_ll->first), ntohl(flow_ll->last));
    flow->first = head->ts;
    timeval_sub_usec(&flow->first, (int64_t)(head->sys_uptime - ntohl(flow_ll->first)) * 1000);
    flow->last = head->ts;
    timeval_sub_usec(&flow->last, (int64_t)(head->sys_uptime - ntohl(flow_ll->last)) * 1000);
    SLOG(LOG_DEBUG, "...yielding: %s->%s", timeval_2_str(&flow->first), timeval_2_str(&flow->last));

    return 0;
}

// the caller must have checked there are
static int nf_msg_head_decode(struct nf_msg *msg, void const *src)
{
    struct nf_msg_ll const *msg_ll = src;   // FIXME: won't work if not properly aligned

    unsigned const version = ntohs(msg_ll->version);
    if (version != 5) {
        SLOG(LOG_DEBUG, "Skip netflow version %u", version);
        return -1;
    }

    CONV_16(msg, version);
    CONV_16(msg, nb_flows);
    CONV_32(msg, sys_uptime);
    msg->ts.tv_sec  = ntohl(msg_ll->ts_sec);
    msg->ts.tv_usec = ntohl(msg_ll->ts_nsec) / 1000;
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
    SLOG(LOG_DEBUG, "Decoding a netflow msg of %zu bytes", size);

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
        if (0 != nf_flow_decode(msg->flows+f, msg, ptr)) return -1;
        ptr += sizeof(struct nf_flow_ll);
    }

    return tot_size;
}

/*
 * Netflow collector
 */

#define MAX_NETFLOW_PDU 8096

int netflow_listen(char const *service, int (*cb)(struct ip_addr const *, struct nf_msg const *, struct nf_flow const *))
{
    int err = -1;

    struct sock sock;
    if (0 != sock_ctor_server(&sock, service)) return -1;

    while (sock_is_opened(&sock)) {
        uint8_t buf[MAX_NETFLOW_PDU];
        struct ip_addr sender;
        ssize_t sz = sock_recv(&sock, buf, sizeof(buf), &sender);
        if (sz < 0) goto quit;
        if (sz == sizeof(buf)) {
            SLOG(LOG_ERR, "Received a PDU that's bigger than expected. Bailing out!");
            goto quit;
        }

        struct nf_msg msg;
        if (netflow_decode_msg(&msg, buf, sz) < 0) {
            SLOG(LOG_DEBUG, "Skipping netflow msg");
            continue;
        }

        for (unsigned f = 0; f < msg.nb_flows; f++) {
            err = cb(&sender, &msg, msg.flows+f);
            if (err < 0) goto quit;
        }
    }

    err = 0;
quit:
    SLOG(LOG_NOTICE, "Quitting netflow listener (err=%d)", err);
    sock_dtor(&sock);
    return err;
}

/*
 * Init
 */

static unsigned inited;
void netflow_init(void)
{
    if (inited++) return;

    log_category_netflow_init();
    sock_init();
}

void netflow_fini(void)
{
    if (--inited) return;

    sock_fini();
    log_category_netflow_fini();
}

