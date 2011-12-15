// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef CNXTRACK_H_111215
#define CNXTRACK_H_111215
#include <stdbool.h>
#include <stdint.h>
#include <junkie/config.h>
#include <junkie/proto/ip.h>    // for struct ip_key
#include <junkie/proto/port_muxer.h>    // for struct port_key
#include <junkie/tools/timeval.h>

/** @file
 * @brief Connection tracking
 *
 * When we have a payload to parse, there is many ways to know
 * which parser is responsable for it:
 *
 * - we can tell from some protocol field (easy)
 * - we can tell from the configuration (easy)
 * - we can tell by trying all parsers and choose one that seams to apply (cpu
 *   hungry, we don't try that in junkie)
 * - we can know because another message told us in the past (easy but can become
 *   memory hungry)
 *
 * This last method is what's called connection tracking.
 * For this to work, we need a memory of what's supposed to happen in the near
 * future.
 *
 * We only define this for TCP/IP here but the same principle might apply for
 * other protocols as well.
 */

struct ip_addr cnxtrack_ip_addr_unknown;
#define ADDR_UNKNOWN (&cnxtrack_ip_addr_unknown)
#define PORT_UNKNOWN 0U

struct cnxtrack_ip;

/// Track a future connection
struct cnxtrack_ip *cnxtrack_ip_new(
    unsigned ip_proto,          ///< IP subprotocol (probably just IPPROTO_TCP or IPPROTO_UDP)
    struct ip_addr const *src,  ///< Source address or ADDR_UNKNOWN
    uint16_t src_port,          ///< Source port or PORT_UNKNOWN
    struct ip_addr const *dst,  ///< Dest address or ADDR_UNKNOWN
    uint16_t dst_port,          ///< Dest port or PORT_UNKNOWN
    bool reuse,                 ///< If not set, the cnxtrack will be deleted once used
    struct proto *proto,        ///< The proto that should handle that payload
    struct timeval const *now   ///< The current time
);

void cnxtrack_ip_del(struct cnxtrack_ip *);

/// Find a suitable proto for this socket, or NULL if none found
struct proto *cnxtrack_ip_lookup(unsigned ip_proto, struct ip_addr const *src, uint16_t src_port, struct ip_addr const *dst, uint16_t dst_port, struct timeval const *now);

void cnxtrack_init(void);
void cnxtrack_fini(void);

#endif
