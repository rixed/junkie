// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef IP_ADDR_H_100511
#define IP_ADDR_H_100511
#include <stdbool.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <junkie/tools/ext.h>
#include <junkie/proto/eth.h>   // for ETH_ADDR_LEN

/** @file
 * @brief Utilities to handle IPv4/6 addresses
 */

/// An IP address
struct ip_addr {
    sa_family_t family;         /// AF_INET for IPv4 and AF_INET6 for IPv6
    union {
        struct in_addr  v4;     /// v4 address
        struct in6_addr v6;     /// v6 address
    } u;
};

/// MACRO to define a struct ip_addr for IPv4 (for instance, IP4(192, 168, 1, 2))
#define IP4(a, b, c, d) { .family = AF_INET, .u.v4.s_addr = (a)|(b<<8)|(c<<16)|(d<<24) }

int ip_addr_ctor_from_str(struct ip_addr *, char const *, size_t, int);
int ip_addr_ctor_from_str_any(struct ip_addr *, char const *);
void ip_addr_ctor_from_ip4(struct ip_addr *, uint32_t);
void ip_addr_ctor_from_ip6(struct ip_addr *, struct in6_addr const *);
int ip_addr_ctor_from_sockaddr(struct ip_addr *, struct sockaddr const *, socklen_t);
int ip_addr_cmp(struct ip_addr const *, struct ip_addr const *);

static inline bool ip_addr_eq(struct ip_addr const *a, struct ip_addr const *b)
{
    return 0 == ip_addr_cmp(a, b);
}

bool ip_addr_is_v6(struct ip_addr const *);
char const *ip_addr_2_str(struct ip_addr const *);
char const *ip_addr_2_strv6(struct ip_addr const *);
bool ip_addr_is_routable(struct ip_addr const *);

/// Tells whether this address is a global or network broadcast.
/* @note We can't tell if this is a subnet broadcast since we never know the subnet mask.
 */
bool ip_addr_is_broadcast(struct ip_addr const *);

bool ip_addr_match_mask(struct ip_addr const *host, struct ip_addr const *net, struct ip_addr const *mask);

/// Tells whether this address is between min and max, inclusives.
bool ip_addr_match_range(struct ip_addr const *host, struct ip_addr const *min, struct ip_addr const *max);

/// convert an IP addr into a SCM number
SCM scm_from_ip_addr_number(struct ip_addr const *ip);

/// convert an IP addr into a SCM pair (FAMILY, number)
SCM scm_from_ip_addr(struct ip_addr const *);

/// and the other way around
int scm_string_2_ip_addr(struct ip_addr *, SCM);

/// more often than not you'll have a netmask with your ip
int scm_netmask_2_ip_addr2(struct ip_addr *net, struct ip_addr *mask, SCM net_, SCM mask_);

/// Convert an eth addr into a SCM number
SCM scm_from_eth_addr(unsigned char const addr[ETH_ADDR_LEN]);

void ip_addr_serialize(struct ip_addr const *addr, uint8_t **buf);
void ip_addr_deserialize(struct ip_addr *addr, uint8_t const **buf);

#endif
