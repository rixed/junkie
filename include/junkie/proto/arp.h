// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef ARP_H_100402
#define ARP_H_100402
#include <junkie/proto/proto.h>
#include <junkie/proto/eth.h>   // for ETH_ADDR_LEN
#include <junkie/tools/ip_addr.h>

/** @file
 * @brief ARP informations
 */

extern struct proto *proto_arp;

/// Description of an ARP message
struct arp_proto_info {
    struct proto_info info;                 ///< Generic infos
    enum arp_opcode { ARP_REQUEST=1, ARP_REPLY=2 } opcode;
    bool proto_addr_is_ip;
    bool hw_addr_is_eth;
    struct ip_addr sender;                  ///< Set iff proto_addr_is_ip
    struct ip_addr target;                  ///< Set iff proto_addr_is_ip
    unsigned char hw_target[ETH_ADDR_LEN];  ///< Set iff opcode == 2
};

// For testing:
enum proto_parse_status arp_parse(struct parser *, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet);

void arp_init(void);
void arp_fini(void);

#endif
