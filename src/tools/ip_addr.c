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
#include <junkie/tools/miscmacs.h>
#include <junkie/tools/tempstr.h>
#include <junkie/tools/ip_addr.h>
#include <junkie/cpp.h>
#include <junkie/tools/log.h>

static char const Id[] = "$Id: 10f0ed302127e3cba365297a48a6d011a88f41a5 $";

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

int ip_addr_ctor_from_str(struct ip_addr *ip, char const *str, size_t len, int version)
{
    memset(ip, 0, sizeof *ip);

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

bool ip_addr_is_v6(struct ip_addr const *addr)
{
    return addr->family == AF_INET6;
}

char const *ip_addr_2_str(struct ip_addr const *addr)
{
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
    if (ip_addr_is_v6(addr)) return false;  // TODO
    uint32_t netmask = netmask_of_address(addr->u.v4);
    return (netmask | ntohl(addr->u.v4.s_addr)) == 0xffffffffU;
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

