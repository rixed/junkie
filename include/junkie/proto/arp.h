// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef ARP_H_100402
#define ARP_H_100402
#include <stdint.h>
#include <netinet/ether.h>
#include <junkie/proto/proto.h>
#include <junkie/tools/ip_addr.h>

/** @file
 * @brief ARP informations
 */

extern struct proto *proto_arp;

/// Description of an ARP message
struct arp_proto_info {
    struct proto_info info;         ///< Generic infos
    uint16_t opcode;                ///< 1 for requests, 2 for responses
    bool proto_addr_is_ip;
    bool hw_addr_is_eth;
    struct ip_addr sender;          ///< Set iff proto_addr_is_ip
    struct ip_addr target;          ///< Set iff proto_addr_is_ip
    uint8_t hw_target[ETH_ALEN];    ///< Set iff operation == 2
};

void arp_init(void);
void arp_fini(void);

#endif
