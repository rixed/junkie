// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef IP_HDR_H_101230
#define IP_HDR_H_101230
#include <stdint.h>
#include "junkie/config.h"
#include "junkie/cpp.h"
#include <netinet/in.h> // For struct in6_addr (same than in ip_addr.h)

// Definition of an IP header
struct ip_hdr {
    uint8_t version_hdrlen;
#   define IP_VERSION_MASK 0xF0U
#   define IP_HDRLEN_MASK  0x0FU
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint8_t flags;
#   define IP_DONT_FRAG_MASK   0x40U
#   define IP_MORE_FRAGS_MASK  0x20U
#   define IP_FRAG_OFFSET_MASK 0x1FU
    uint8_t frag_offset_lo;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
    // Then options
} packed_;

#define IP_HDR_LENGTH(ip) ((READ_U8(&ip->version_hdrlen) & IP_HDRLEN_MASK) * 4)
#define IP_VERSION(ip)    (READ_U8(&ip->version_hdrlen) >> 4)

// Definition of an IPv6 header
struct ipv6_hdr {
    uint8_t version_class;
#   define IP6_VERSION_MASK 0xF0U
#   define IP6_CLASS_MASK   0x0FU
    uint8_t flow[3];
    uint16_t payload_len;
    uint8_t next;
    uint8_t hop_limit;
    struct in6_addr src;
    struct in6_addr dst;
} packed_;

#define IP6_CLASS(ip)   (READ_U8(&ip->version_class) & IP6_CLASS_MASK)
#define IP6_VERSION(ip) (READ_U8(&ip->version_class) >> 4)

// Definition of an ICMP header
struct icmp_hdr {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t id, seqnum;  // for message with an id and/or a seqnum
} packed_;

// Definition of an UDP header
struct udp_hdr
{
  uint16_t src;
  uint16_t dst;
  uint16_t len;
  uint16_t checksum;
} packed_;

// Definition of a TCP header
struct tcp_hdr {
    uint16_t src;
    uint16_t dst;
    uint32_t seq_num;
    uint32_t ack_seq;
    uint8_t hdr_len;
#   define TCP_HDR_LENGTH_MASK 0xF0U
    uint8_t flags;
#   define TCP_URG_MASK  0x20U
#   define TCP_ACK_MASK  0x10U
#   define TCP_PSH_MASK  0x08U
#   define TCP_RST_MASK  0x04U
#   define TCP_SYN_MASK  0x02U
#   define TCP_FIN_MASK  0x01U
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
} packed_;

#define TCP_HDR_LENGTH(tcp) ((READ_U8(&(tcp)->hdr_len) >> 4U) * 4)

#endif
