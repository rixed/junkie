// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef PORT_MUXER_101201
#define PORT_MUXER_101201

/** @file
 * @brief A tool for UDP/TCP multiplexers to choose a subproto based on port.
 *
 * Subparsers are spawned by TCP/UDP based on their port. By default, every
 * parser that have a well known port is supposed to register this well known
 * port to UDP and/or TCP multiplexers, but this configuration is also made
 * available to guile in order for other ports and/or port ranges to be added.
 * TCP/UDP multiplexer will then choose the first proto on this list that accept
 * the packet.
 */

#include <stdbool.h>
#include <junkie/proto/proto.h>
#include <junkie/tools/mutex.h>
#include <junkie/tools/queue.h>

/// A list of port_muxer structs
struct port_muxer_list {
    struct mutex mutex;
    TAILQ_HEAD(port_muxers, port_muxer) muxers;
};

void port_muxer_list_ctor(struct port_muxer_list *, char const *name);
void port_muxer_list_dtor(struct port_muxer_list *);

/// This structure associate a proto for each port range.
struct port_muxer {
    TAILQ_ENTRY(port_muxer) entry;
    uint16_t port_min, port_max;
    struct proto *proto;
    bool malloced;  ///< Tru if it was malloced (ie. created from guile)
};

void port_muxer_ctor(struct port_muxer *, struct port_muxer_list *, uint16_t port_min, uint16_t port_max, struct proto *proto);
void port_muxer_dtor(struct port_muxer *, struct port_muxer_list *);

struct port_muxer *port_muxer_new(struct port_muxer_list *, uint16_t port_min, uint16_t port_max, struct proto *proto);
void port_muxer_del(struct port_muxer *, struct port_muxer_list *);

/** Retrieve the lastly inserted proto handling this port.
 * FIXME: add a pointer to the lastly returned proto and return the next one (in a cursor fashion)
 */
struct proto *port_muxer_find(struct port_muxer_list *, uint16_t port);

#include <libguile.h>
SCM g_port_muxer_list(struct port_muxer_list *);
SCM g_port_muxer_add(struct port_muxer_list *, SCM name, SCM port_min, SCM port_max);
SCM g_port_muxer_del(struct port_muxer_list *, SCM name, SCM port_min, SCM port_max);

void port_muxer_init(void);
void port_muxer_fini(void);

#endif
