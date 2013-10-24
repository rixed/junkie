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
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include "junkie/cpp.h"
#include "junkie/tools/miscmacs.h"
#include "junkie/tools/tempstr.h"
#include "junkie/tools/ip_addr.h"
#include "junkie/tools/log.h"

void ip_addr_ctor_from_ip4(struct ip_addr *ip_addr, uint32_t ip4)
{
    memset(ip_addr, 0, sizeof(*ip_addr));
    ip_addr->family = AF_INET;
    ip_addr->u.v4.s_addr = ip4;
}

void ip_addr_ctor_from_ip6(struct ip_addr *ip_addr, struct in6_addr const *ip6)
{
    memset(ip_addr, 0, sizeof(*ip_addr));
    ip_addr->family = AF_INET6;
    ip_addr->u.v6 = *ip6;
}

// Note: if version is 0 then try both v4 and v6
int ip_addr_ctor_from_str(struct ip_addr *ip, char const *str, size_t len, int version)
{
    memset(ip, 0, sizeof *ip);

    // Copy the string to add the null terminator
    char dup[len+1];
    strncpy(dup, str, len);
    dup[len] = 0;
    int err;

    switch (version) {
    case 4:
        ip->family = AF_INET;
        err = inet_pton(AF_INET, dup, &ip->u.v4);
        break;
    case 6:
        ip->family = AF_INET6;
        err = inet_pton(AF_INET6, dup, &ip->u.v6);
        break;
    case 0:
        ip->family = AF_INET;
        err = inet_pton(AF_INET, dup, &ip->u.v4);
        if (err != 1) {
            ip->family = AF_INET6;
            err = inet_pton(AF_INET6, dup, &ip->u.v6);
        }
        break;
    default:
        SLOG(LOG_DEBUG, "invalid mode (%d)", version);
        abort();
    }

    if (err == -1) {
        SLOG(LOG_WARNING, "Cannot convert string to IP address: %s", strerror(errno));
        return -1;
    } else if (err == 0) {
        SLOG(LOG_WARNING, "Cannot convert string to IP address: Invalid string '%.*s'", (int)len, str);
        return -1;
    }

    return 0;
}

int ip_addr_ctor_from_str_any(struct ip_addr *ip, char const *str)
{
    if (1 == inet_pton(AF_INET, str, &ip->u.v4)) {
        ip->family = AF_INET;
        return 0;
    }
    if (1 == inet_pton(AF_INET6, str, &ip->u.v6)) {
        ip->family = AF_INET6;
        return 0;
    }

    SLOG(LOG_WARNING, "Cannot convert string to IP address: %s", strerror(errno));
    return -1;
}

int ip_addr_ctor_from_sockaddr(struct ip_addr *ip, struct sockaddr const *addr, socklen_t addrlen)
{
    switch (addr->sa_family) {
        case AF_INET:
            {
                struct sockaddr_in *ip_addr = (struct sockaddr_in *)addr;
                if (addrlen < sizeof(*ip_addr)) {
                    SLOG(LOG_NOTICE, "Invalid AF_INET sockaddr of size %zu", (size_t)addrlen);
                    return -1;
                }
                ip_addr_ctor_from_ip4(ip, ip_addr->sin_addr.s_addr);
                return 0;
            }
        case AF_INET6:
            {
                struct sockaddr_in6 *ip_addr = (struct sockaddr_in6 *)addr;
                if (addrlen < sizeof(*ip_addr)) {
                    SLOG(LOG_NOTICE, "Invalid AF_INET6 sockaddr of size %zu", (size_t)addrlen);
                    return -1;
                }
                ip_addr_ctor_from_ip6(ip, &ip_addr->sin6_addr);
                return 0;
            }
    }

    SLOG(LOG_DEBUG, "Unknown sockaddr family %u", (unsigned)addr->sa_family);
    return -1;
}

static int saturate(int v)
{
    if (v == 0) return 0;
    else if (v > 0) return 1;
    else return -1;
}

int ip_addr_cmp(struct ip_addr const *a, struct ip_addr const *b)
{
    if (a->family < b->family) return -1;
    else if (a->family > b->family) return 1;
    else switch (a->family) {
        case AF_INET:
            return saturate(memcmp(&a->u.v4, &b->u.v4, sizeof(a->u.v4)));
        case AF_INET6:
            return saturate(memcmp(&a->u.v6, &b->u.v6, sizeof(a->u.v6)));
    }
    FAIL("Invalid IP family (%d)", a->family);
    return -1;
}

extern inline bool ip_addr_eq(struct ip_addr const *, struct ip_addr const *);

bool ip_addr_is_v6(struct ip_addr const *addr)
{
    return addr->family == AF_INET6;
}

char const *ip_addr_2_str(struct ip_addr const *addr)
{
    if (! addr) return "null";

    char *str = tempstr();
    if (NULL == inet_ntop(addr->family, &addr->u, str, TEMPSTR_SIZE)) {
        SLOG(LOG_ERR, "Cannot inet_ntop(): %s", strerror(errno));
        return "INVALID";
    }
    return str;
}

char const *ip_addr_2_strv6(struct ip_addr const *addr)
{
    if (ip_addr_is_v6(addr)) return ip_addr_2_str(addr);

    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "::ffff:%"PRINIPQUAD, NIPQUAD(&addr->u.v4));
    return str;
}

bool ip_addr_is_routable(struct ip_addr const *addr)
{
    if (ip_addr_is_v6(addr)) return true;
    uint32_t const a = ntohl(addr->u.v4.s_addr);
    /* Non routable IP addresses :
     * private addresses :
     * 10.0.0.0    to 10.255.255.255  ie 0x0a000000 to 0x0affffff
     * 172.16.0.0  to 172.31.255.255  ie 0xac100000 to 0xac1fffff
     * 192.168.0.0 to 192.168.255.255 ie 0xc0a80000 to 0xc0a8ffff
     * loopback :
     * 127.0.0.0   to 127.255.255.255 ie 0x7f000000 to 0x7fffffff
     * other non-routable :
     * 169.254.0.0 to 169.254.255.255 ie 0xa9fe0000 to 0xa9feffff
     */
    return
        (a < 0x0a000000U || a > 0x0affffffU) &&
        (a < 0xac100000U || a > 0xac1fffffU) &&
        (a < 0xc0a80000U || a > 0xc0a8ffffU) &&
        (a < 0x7f000000U || a > 0x7fffffffU) &&
        (a < 0xa9fe0000U || a > 0xa9feffffU);
}

// returns the netmask (in host byte order)
static uint32_t netmask_of_address(struct in_addr v4)
{
    uint8_t const first = ((uint8_t *)(void *)(&v4.s_addr))[0];
    if ((first & 0x80) == 0) return 0xff000000U;
    if ((first & 0x40) == 0) return 0xffff0000U;
    return 0xffffff00U;
}

bool ip_addr_is_broadcast(struct ip_addr const *addr)
{
    if (ip_addr_is_v6(addr)) {
        static uint8_t all_nodes[16] = {
            0xff, 0x02, 0, 0, 0, 0, 0, 0,
               0,    0, 0, 0, 0, 0, 0, 1,
        };
        ASSERT_COMPILE(sizeof(all_nodes) == sizeof(addr->u.v6.s6_addr));
        return 0 == memcmp(addr->u.v6.s6_addr, all_nodes, sizeof(all_nodes));
    } else {
        uint32_t netmask = netmask_of_address(addr->u.v4);
        return (netmask | ntohl(addr->u.v4.s_addr)) == 0xffffffffU;
    }
}

static bool match_mask_byte(uint8_t const *host, uint8_t const *net, uint8_t const *mask, unsigned nb_bytes)
{
    if (nb_bytes == 0) return true;
    if ((*net & *mask) != (*host & *mask)) return false;
    return match_mask_byte(host+1, net+1, mask+1, nb_bytes-1);
}

bool ip_addr_match_mask(struct ip_addr const *host, struct ip_addr const *net, struct ip_addr const *mask)
{
    assert(net->family == mask->family);
    if (host->family != net->family) return false;

    if (host->family == AF_INET) {
        return match_mask_byte((uint8_t *)&host->u.v4.s_addr, (uint8_t *)&net->u.v4.s_addr, (uint8_t *)&mask->u.v4.s_addr, 4);
    } else {
        return match_mask_byte(host->u.v6.s6_addr, net->u.v6.s6_addr, mask->u.v6.s6_addr, 16);
    }
}

bool ip_addr_match_range(struct ip_addr const *host, struct ip_addr const *min, struct ip_addr const *max)
{
    assert(min->family == max->family);
    if (host->family != min->family) return false;

    // Addresses are stored in network byte order (big endian) so we can compare than with memcmp whatever the size
    return
        memcmp(&host->u, &min->u, host->family == AF_INET ? 4:16) >= 0 &&
        memcmp(&host->u, &max->u, host->family == AF_INET ? 4:16) <= 0;
}

SCM scm_from_ip_addr_number(struct ip_addr const *ip)
{
    if (ip->family == AF_INET) {
        return scm_from_uint32(ntohl(ip->u.v4.s_addr));
    } else {
        uint32_t w4, w3, w2, w1;
        memcpy(&w4, ((char *)ip->u.v6.s6_addr)+0*sizeof(w4), sizeof(w4));
        memcpy(&w3, ((char *)ip->u.v6.s6_addr)+1*sizeof(w4), sizeof(w3));
        memcpy(&w2, ((char *)ip->u.v6.s6_addr)+2*sizeof(w4), sizeof(w2));
        memcpy(&w1, ((char *)ip->u.v6.s6_addr)+3*sizeof(w4), sizeof(w1));
        uint64_t hi = ((uint64_t)ntohl(w4) << 32ULL) | ntohl(w3);
        uint64_t lo = ((uint64_t)ntohl(w2) << 32ULL) | ntohl(w1);
        return scm_logior(scm_ash(scm_from_uint64(hi), scm_from_uint(64)), scm_from_uint64(lo));
    }
}

SCM scm_from_ip_addr(struct ip_addr const *ip)
{
    return scm_cons(scm_from_int(ip->family), scm_from_ip_addr_number(ip));
}

int scm_string_2_ip_addr(struct ip_addr *ip, SCM ip_)
{
    char *ip_str = scm_to_tempstr(ip_);
    if (0 != ip_addr_ctor_from_str_any(ip, ip_str)) return -1;
    return 0;
}

int scm_netmask_2_ip_addr2(struct ip_addr *net, struct ip_addr *mask, SCM net_, SCM mask_)
{
    if (0 != scm_string_2_ip_addr(net, net_)) return -1;
    if (0 != scm_string_2_ip_addr(mask, mask_)) return -1;
    if (net->family != mask->family) return -1;
    return 0;
}


// While we are at it, convert from eth addr to SCM (as a uint64!)
SCM scm_from_eth_addr(unsigned char const addr[ETH_ADDR_LEN])
{
#   define A(idx, loc) (((uint64_t)addr[idx])<<((loc)*8))
    uint64_t const v = A(0,5) | A(1,4) | A(2,3) | A(3,2) | A(4,1) | A(5,0);
    return scm_from_uint64(v);
#   undef A
}
