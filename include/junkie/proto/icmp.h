// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef ICMP_H_100514
#define ICMP_H_100514
#include <stdint.h>
#include <junkie/proto/proto.h>
#include <junkie/tools/ip_addr.h>

/** @file
 * @brief ICMP informations
 */

extern struct proto *proto_icmp;
extern struct proto *proto_icmpv6;

/// ICMP message
struct icmp_proto_info {
    struct proto_info info;     ///< Header size correspond to the whole message since ICMP have no actual payload
    uint8_t type, code;         ///< ICMP type and code
    uint16_t id;                ///< Most ICMP messages comes with a 16bits Id.
#   define ICMP_ERR_SET      0x1  // at least protocol and addr
#   define ICMP_ERR_PORT_SET 0x2
#   define ICMP_ID_SET       0x4
    unsigned set_values;        ///< Mask of the field that are actually defined in this struct
    struct icmp_err {
        uint8_t protocol;       ///< The protocol that triggered the error
        struct ip_addr addr[2]; ///< The IP addresses (src, dest) that triggered the error
        uint16_t port[2];       ///< The ports that triggered the error (defined if set_values & ICMP_ERR_PORT_SET)
    } err;                      ///< Defined if set_values & ICMP_ERR_SET
};

#define icmpv6_proto_info icmp_proto_info   ///< For ASSIGN_INFO MACROs

// Used by ICMPv6
char *icmp_err_2_str(struct icmp_err const *, unsigned set_values);
int icmp_extract_err_ports(struct icmp_err *, uint8_t const *packet);

// For testing
enum proto_parse_status icmp_parse(struct parser *, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet);
enum proto_parse_status icmpv6_parse(struct parser *, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet);

void icmp_init(void);
void icmp_fini(void);

void icmpv6_init(void);
void icmpv6_fini(void);

#endif
