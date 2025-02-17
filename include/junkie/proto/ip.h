// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef IP_H_100402
#define IP_H_100402
#include <stdbool.h>
#include <junkie/tools/ip_addr.h>
#include <junkie/tools/queue.h>
#include <junkie/proto/proto.h>
#include <junkie/cpp.h>

/** @file
 * @brief IP informations
 */

/// We use a dedicated log category for all IP parsing related messages (@see log.h)
LOG_CATEGORY_DEC(proto_ip);

extern struct proto *proto_ip;
extern struct proto *proto_ip6;

/*
 * Proto Info
 */

/// IP packet description
struct ip_proto_info {
    struct proto_info info;     ///< Header and payload sizes
    struct ip_key {
        struct ip_addr addr[2]; ///< Source and destination addresses
        unsigned protocol;      ///< Embodied protocol
    } packed_ key;              ///< Note that this struct ip_key is packet so that it can easily serve as a hash key or the like
    unsigned version;           ///< IP version (will be 4 or 6)
    unsigned ttl;               ///< Time To Live
    unsigned way;               ///< 0 or 1, The way used to store the mux subparsers (key.addr[way] is the source of the packet)
    enum ip_fragmentation {
        IP_NOFRAG,              ///< If the received packet was not a fragment (with dont_frag flag not set)
        IP_DONTFRAG,            ///< If the received packet has the dont_frag flag set (and so was not fragmented)
        IP_FRAGMENT,            ///< If this is a fragment
        IP_REASSEMBLED,         ///< If this was reassembled
    } fragmentation;            ///< Only set if v4
    unsigned id;                ///< Identification field (useful for OS detection) (only set if v4)
    uint8_t traffic_class;      ///< aka. TOS for IPv4
};

/// IPv6 and IPv4 uses the same proto_info. This define is required for ASSIGN_* MACROS.
#define ip6_proto_info ip_proto_info

/// Look for the mux_subparser handling connections between IP addresses src and dst for given protocol
/** if proto is given, then restrict the lookup to this proto, and creates a new one if not found.
 * @return NULL if not found and not asked to create a new one. */
struct mux_subparser *ip_subparser_lookup(struct parser *parser, struct proto *proto, struct proto *requestor, unsigned protocol, struct ip_addr const *src, struct ip_addr const *dst, unsigned *way, struct timeval const *now);

/// Only useful for proto/ip6
void const *ip_info_addr(struct proto_info const *, size_t *);
char const *ip_info_2_str(struct proto_info const *);
char const *ip_proto_2_str(unsigned protocol);
unsigned ip_key_ctor(struct ip_key *, unsigned protocol, struct ip_addr const *, struct ip_addr const *);

/// A proto that wants to register itself for receiving IP payload for some protocol must define this
struct ip_subproto {
    LIST_ENTRY(ip_subproto) entry;  ///< Entry in the list of IP subprotos
    unsigned protocol;              ///< Protocol implemented by the subproto
    struct proto *proto;            ///< The subproto
};

/// Construct an ip_subproto (and register this proto as subproto for the given protocol of IPv4)
void ip_subproto_ctor(struct ip_subproto *ip_subproto, unsigned protocol, struct proto *proto);

/// Destruct an ip_subproto (and unregister this protos)
void ip_subproto_dtor(struct ip_subproto *ip_subproto);

/// Parsing functions (available for tests)
enum proto_parse_status ip_parse(struct parser *, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *);

enum proto_parse_status ip6_parse(struct parser *, struct proto_info *parent, unsigned unused_ way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet);

// Also for tests:
extern struct mux_proto mux_proto_ip;

/// Construct an ip_subproto (and register this proto as subproto for the given protocol of IPv6)
void ip6_subproto_ctor(struct ip_subproto *ip_subproto, unsigned protocol, struct proto *proto);

/// Destruct an ip_subproto (and unregister this protos)
void ip6_subproto_dtor(struct ip_subproto *ip_subproto);

void ip_init(void);
void ip_fini(void);

void ip6_init(void);
void ip6_fini(void);

#endif
