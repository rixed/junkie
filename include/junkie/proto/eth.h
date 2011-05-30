// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef ETH_H_100402
#define ETH_H_100402
#include <junkie/proto/proto.h>
#include <junkie/tools/queue.h>

/** @file
 * @brief Ethernet informations
 */

extern struct proto *proto_eth;

/// Length of an Ethernet address
#define ETH_ADDR_LEN 6

/// Values for protocol
#define ETH_PROTO_IPv4  0x0800
#define ETH_PROTO_IPv6  0x86DD
#define ETH_PROTO_ARP   0x0806
#define ETH_PROTO_8021Q 0x8100

/// Ethernet frame
struct eth_proto_info {
    struct proto_info info;                 ///< Header and payload sizes
#   define VLAN_UNSET (-1)
    int vlan_id;                            ///< Vlan identifier (or VLAN_UNSET if unset)
    unsigned char addr[2][ETH_ADDR_LEN];    ///< src/dest MAC addresses
    unsigned protocol;                      ///< Embedded protocol
};

/// Other protos can register themselves as Eth subprotos by defining this struct
struct eth_subproto {
    LIST_ENTRY(eth_subproto) entry; ///< Entry in the list of all Eth subprotos
    unsigned protocol;              ///< Protocol id implemented by the subproto
    struct proto *proto;            ///< the subproto
};

/// Construct an eth_subproto (registering the protocol implementation)
void eth_subproto_ctor(struct eth_subproto *eth_subproto, unsigned protocol, struct proto *proto);

/// Destruct an eth_subproto (deregistering the protocol implementation)
void eth_subproto_dtor(struct eth_subproto *eth_subproto);

/// Spawn a new eth parser for given vlan_id
struct mux_subparser *eth_subparser_and_parser_new(struct parser *, struct proto *proto, struct proto *requestor, int vlan_id, struct timeval const *now);

/// Convert an eth address into a displayable string
char const *eth_addr_2_str(unsigned char const addr[ETH_ADDR_LEN]);

void eth_init(void);
void eth_fini(void);

#endif
