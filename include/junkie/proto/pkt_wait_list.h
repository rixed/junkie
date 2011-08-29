// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef PKT_WAIT_LIST_H_101231
#define PKT_WAIT_LIST_H_101231
#include <stdbool.h>
#include <junkie/config.h>
#include <junkie/tools/queue.h>
#include <junkie/tools/timeval.h>
#include <junkie/tools/mutex.h>
#include <junkie/proto/proto.h>

/** @file
 * @brief Waiting lists for packets
 *
 * IP, TCP and many other protocols on UDP can receive packets in the wrong
 * order and must reorder the data before calling their subparsers so that
 * those can understand their protocol.  The basic idea is thus to maintain a
 * list of out of order packets in the mux_subparsers, provisioned with all
 * arriving packets and dequeuing the head of the list whenever complete. The
 * purpose of this list is thus to reorder and wait for missing packets,
 * according to an "offset" in the stream that can be TCP sequence number, IP
 * fragment offset, WTP sequence number...  The user callbacks will not be
 * called until the hole in the stream is completed.  When the pending packets
 * are discarded, the subparser is not called but the okfn is, which imply
 * that:
 *
 * - the callback is still called once per received packet;
 *
 * - the callback may be called for packets which cap->tv are no more
 * ascending.
 *
 * This simple scheme leads to some difficulties since, for performance
 * reasons, all data that are build by the parsers for the callbacks are stored
 * on the stack.  Thus, when suspending the parse of a packet we must copy the
 * proto_info structures from the stack to the heap, taking care of the
 * pointers in them.  Another problem, easier to solve but probably more
 * expensive, is that due to the way the kernel sends the packets to libpcap we
 * also need to copy the packet itself.
 *
 * That's why we will try to only push the packets in the waiting list when
 * this is strictly required (or equivalently, the enqueue function will first
 * check if the offset of the packet to be pushed match next_offset, and if so
 * will directly call the subparser).
 */

/// A Waiting Packet.
/** When a packet is enqueued on a waiting list, it is first copied out of the
 * pcap mmap, then all the proto_info description must also be copied out of
 * the stack. We also must preserve all the parameters that are required to
 * eventually call proto_parse, when the missing packets will be received.
 * Everything must be freed when the pkt_wait is deleted, and the subparser
 * must be called whatever the fate of this pkt_wait (parsed, timeouted,
 * deleted in any way...). */
struct pkt_wait {
    /// Entry in the pkt_wait_list
    LIST_ENTRY(pkt_wait) entry;
    /// Where in the "stream" this packet is located. When offset = list->next_offset, then the packet is parsable.
    unsigned offset;
    /// Next expected offset following this packet
    /// (this in not necessarily offset+wire_len for instance if we have message sequence numbers instead of bytes sequence numbers)
    unsigned next_offset;
    /// How many bytes were captured on original packet (ie size of the packet field)
    size_t tot_cap_len;
    /// How many bytes of the saved total packet were already parsed
    size_t start;
    /// How many bytes available
    size_t cap_len;
    /// How many bytes were available on the wire
    size_t wire_len;
    /// Where do we need to start parsing into the original packet
    /** The callback must not be called when the packet is put on hold, until :
     * - the head of the packet list is complete and the first packets are dequeued;
     * - the list is deleted, for instance when timeouted. */
    /// Current proto_info at the time when the packet was put on hold
    struct proto_info *parent;
    /// Current way at the time when the packet was put on hold
    unsigned way;
    /// Current okfn at the time when the packet was put on hold (FIXME: is it safe to store this, since the plugin might have been unpluged by the time ?)
    proto_okfn_t *okfn;
    /// The copy of the total captured packet
    uint8_t packet[];
};

struct pkt_wl_config {
    struct pkt_wl_config_list {
        /// The list of struct pkt_wait_list, in LRU-first order.
        TAILQ_HEAD(pkt_wait_list_list, pkt_wait_list) list;
        /// The mutex that protects the above list
        struct mutex mutex;
    } lists[CPU_MAX];
    /// Entry in the list of all pkt_wl_configs
    SLIST_ENTRY(pkt_wl_config) entry;
    /// A sequence to choose a lists at random
    unsigned list_seqnum;
    /// A name to find it from guile
    char const *name;
#   ifndef __GNUC__
    /// The following fields must be read/set atomicaly
    struct mutex atomic;
#   endif
    /// To prevent reentry
    unsigned timeouting; // 1 or 0
    /// Acceptable gap between two successive packets
    unsigned acceptable_gap;
    /// Max number of pending packets
    unsigned nb_pkts_max;
    /// Max pending payload
    size_t payload_max;
    /// Timeout (s)
    unsigned timeout;
};

void pkt_wl_config_ctor(
    struct pkt_wl_config *,         ///< The pkt_wait_list global conf structure to initialize
    char const *name,               ///< The name used to change this pkt_wait_list configurarion
    unsigned acceptable_gap,        ///< Accept to enqueue a packet only if its not further away from previous one (0 for no check)
    unsigned nb_pkts_max,           ///< Max number of pending packets (0 for unlimited)
    size_t payload_max,             ///< Max pending payload (0 for unlimited)
    unsigned timeout                ///< Timeout these pkt_wait_lists after this number of seconds (0 for no timeout)
);

void pkt_wl_config_dtor(struct pkt_wl_config *);

/// A List of Waiting Packets
/** This structure is used to store packets of a same stream that are out of
 * order, until the missing bits are received. Top of the list packets are
 * dequeued as soon as their position in the stream match the waited one, and
 * inserted in the list according to their location in the stream.
 * We do also store a ref to the intended subparser despite the pkt_wait_lists
 * being stored in a mux_subparser leading to it, both for simplicity and
 * generality. */
struct pkt_wait_list {
    /// The list of pkt_wait
    LIST_HEAD(pkt_waits, pkt_wait) pkts;
    /// The global configuration for this pkt_wait_list (never changes during the lifetime of the object)
    struct pkt_wl_config *config;
    /// The list into this config where this pkt_list is queued
    struct pkt_wl_config_list *list;
    /// And the entry in this list
    TAILQ_ENTRY(pkt_wait_list) entry;
    /// Current number of pending packets
    unsigned nb_pkts;
    /// Current pending payload
    size_t tot_payload;
    /// The offset we are currently waiting for to resume parsing
    unsigned next_offset;
    /// Last time we added a packet to the list
    struct timeval last_used;
    /// A Ref to the parser this packet is intended to
    struct parser *parser;
};

/// Construct a pkt_wait_list
int pkt_wait_list_ctor(
    struct pkt_wait_list *pkt_wl,   ///< The waiting list to construct
    unsigned next_offset,           ///< The initial offset we are waiting for
    struct pkt_wl_config *config,   ///< Where we store the pkt_wait_list created with these parameters (useful for timeouting) as well as global conf
    struct parser *parser,          ///< The parser that's supposed to parse this packet whenever possible
    struct timeval const *now       ///< To set the last used time
);

/// Destruct a pkt_wait_list, calling the okfn for every pending packets.
void pkt_wait_list_dtor(struct pkt_wait_list *, struct timeval const *now);

/// Enqueue a packet (or deal with it immediately if possible)
/** This function may call the subparser immediately if no waiting is required.
 * Also, it may call the continuation (skipping subparser) immediately if the
 * offset looks erroneous (ie. either in the past or too much in the future -
 * more than the defined acceptable gap).
 * Set can_parse to false if you want to prevent all call to subparser
 * (erroneous packets will still be "parsed", though). */
enum proto_parse_status pkt_wait_list_add(
    struct pkt_wait_list *pkt_wl,   ///< The packet list where to insert this packet
    unsigned offset,                ///< Offset in the stream of this packet
    unsigned next_offset,           ///< Offset in the stream of the following packet
    bool can_parse,                 ///< True if we are allowed to parse this packet (and others that were pending) if possible
    struct proto_info *parent,      ///< The proto_info of its parent (likely the caller of this function)
    unsigned way,                   ///< Direction identifier (see proto_parse())
    uint8_t const *packet,          ///< The origin packet
    size_t cap_len,                 ///< It's length
    size_t wire_len,                ///< It's actual length on the wire
    struct timeval const *now,      ///< The current time
    proto_okfn_t *okfn,             ///< The "continuation"
    size_t tot_cap_len,             ///< The capture length of the whole packet
    uint8_t const *tot_packet       ///< The whole packet (as given to okfn)
);

/// Tells if the wait list is complete between these two offsets.
/** @note this checks weither all packets were received, not if enough bytes
 * were captured from them. */
bool pkt_wait_list_is_complete(struct pkt_wait_list *, unsigned start_offset, unsigned end_offset);

/// Return a MALLOCED buffer with the reassembled bytes
/** At offset 0, you will have the byte at start_offset.
 * @return NULL if reassembly is not possible, either because some packets are missing
 * or some required parts of the packets were not captured. */
uint8_t *pkt_wait_list_reassemble(struct pkt_wait_list *, unsigned start_offset, unsigned end_offset);

/** Flush a waiting list, ie call proto_parse without subparser for all packets,
 * expect for the last one (if payload if not NULL) which is given to subparser with the payload.
 * Subparser is unrefed in all cases. */
enum proto_parse_status pkt_wait_list_flush(
    struct pkt_wait_list *pkt_wl,   ///< The waiting list
    uint8_t *payload,               ///< Optional payload for the last packet
    size_t cap_len,                 ///< It's length (if payload is set)
    size_t wire_len,                ///< It's actual length on the wire (if payload is set)
    struct timeval const *now       ///< The current time
);

/// Removes a packet from a list, without calling the subparser.
void pkt_wait_del(struct pkt_wait *, struct pkt_wait_list *);

void pkt_wait_list_init(void);
void pkt_wait_list_fini(void);

#endif
