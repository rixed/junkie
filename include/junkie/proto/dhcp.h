// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef DHCP_H_130802
#define DHCP_H_130802
#include <junkie/proto/proto.h>
#include <junkie/proto/eth.h>
#include <junkie/tools/ip_addr.h>

/** @file
 * @brief DHCP informations
 */

extern struct proto *proto_dhcp;

/// Description of a DHCP message
struct dhcp_proto_info {
    struct proto_info info;                 ///< Generic infos
    enum dhcp_opcode { BOOTP_REQUEST=1, BOOTP_REPLY=2 } opcode;
    enum dhcp_msg_type {
        DHCP_DISCOVER = 1, DHCP_OFFER, DHCP_REQUEST,
        DHCP_ACK, DHCP_NAK, DHCP_DECLINE,
        DHCP_RELEASE, DHCP_INFORM,
    } msg_type;
    bool hw_addr_is_eth;
    uint32_t xid;
#   define DHCP_CLIENT_SET     0x01
    uint8_t set_values;
    struct ip_addr client;  ///< yiaddr
    unsigned char client_mac[ETH_ADDR_LEN]; // chaddr
    char server_name[64];
};

void dhcp_init(void);
void dhcp_fini(void);

#endif
