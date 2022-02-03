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
 * those can understand their payload.  The basic idea is thus to maintain a
 * list of out of order packets in the mux_subparsers, provisioned with all
 * incoming packets and dequeuing the head of the list whenever complete. The
 * purpose of this list is thus to reorder and wait for missing packets,
 * according to an "offset" in the stream that can be TCP sequence number, IP
 * fragment offset, WTP sequence number...  The user callbacks will not be
 * called until the hole in the stream is filled in.  When the pending packets
 * are discarded, the subparser is not called but the subscribers of the last
 * proto_info are, which imply that the subscibers may be called for packets
 * which cap->tv are no longer ascending.
 *
 * This simple scheme leads to some difficulties since, for performance
 * reasons, all data that is build by the parsers for the callbacks are stored
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
 *
 * Additionally, a queued packet can be set to wait for another waiting list
 * reaching a given offset. This is useful for TCP since we do not want to parse
 * in a direction ahead of time compared to the other direction.
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
    /// Optionally, wait for another waiting list to reach some offset
    bool sync;              ///< Do way for wl->sync_wl to catch up with sync_offset (because even if wl->sync_wl != NULL we may not want to sync (for instance until we know seqnums in wl->sync_wl)
    unsigned sync_offset;   ///< Only set if wl->sync_wl != NULL && sync
    /// How many bytes were captured on original packet (ie size of the packet field)
    size_t tot_cap_len;
    /// How many bytes of the saved total packet were already parsed
    size_t start;
    /// How many bytes available
    size_t cap_len;
    /// How many bytes were available on the wire
    size_t wire_len;
    /// Timestamp of the packet (same as in cap_info)
    struct timeval cap_tv;
    /// Where do we need to start parsing into the original packet
    /** The callback must not be called when the packet is put on hold, until :
     * - the head of the packet list is complete and the first packets are dequeued;
     * - the list is deleted, for instance when timeouted. */
    /// Current proto_info at the time when the packet was put on hold
    struct proto_info *parent;
    /// Current way at the time when the packet was put on hold
    unsigned way;
    /// The copy of the total captured packet
    uint8_t packet[];
};

struct pkt_wl_config {
    struct pkt_wl_config_list {
        /// The list of struct pkt_wait_list in no particular order (but on 10 different lists, considered for timeout at 1s interval - a low tech way to timeout incrementally)
        LIST_HEAD(pkt_wait_list_list, pkt_wait_list) list[10];
        /// The mutex that protects the above list
        struct supermutex mutex;
        /// the max timestamp of packet addition in any of these waiting lists (used to give current time to timeouter thread)
        struct timeval last_used;
    } lists[CPU_MAX*11];
    /// Index of next list to be timeouted (1s interval between these lists)
    unsigned next_to;
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
    /// Acceptable gap between two successive packets
    unsigned acceptable_gap;
    /// Max number of pending packets
    unsigned num_pkts_max;
    /// Max pending payload
    size_t payload_max;
    /// Can we parse only a subset of the packets or must we wait for the grand reassembly (note: IP -> false, TCP -> true)
    bool allow_partial;
    /// Timeout (s)
    unsigned timeout;
    /// A thread to timeout WLs more aggressively (otherwise pending packets on a WL which receive no more traffic would have to wait until its parent destruction)
    bool has_timeouter;             ///< Flag used for thread destruction
    pthread_t timeouter_pth;        ///< Only set if has_timeouter
};

void pkt_wl_config_ctor(
    struct pkt_wl_config *,         ///< The pkt_wait_list global conf structure to initialize
    char const *name,               ///< The name used to change this pkt_wait_list configurarion
    unsigned acceptable_gap,        ///< Accept to enqueue a packet only if its not further away from previous one (0 for no check)
    unsigned num_pkts_max,           ///< Max number of pending packets (0 for unlimited)
    size_t payload_max,             ///< Max pending payload (0 for unlimited)
    unsigned timeout,               ///< Timeout these pkt_wait_lists after this number of seconds (0 for no timeout)
    bool allow_partial              ///< Should we parse packets as soon as possible or wait for a full PDU?
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
    LIST_ENTRY(pkt_wait_list) entry;
    /// Current number of pending packets
    unsigned num_pkts;
    /// Current pending payload
    size_t tot_payload;
    /// The offset we are currently waiting for to resume parsing
    unsigned next_offset;
    /// A ref to the parser this packet is intended to
    struct parser *parser;
    /// Optionally, the other pkt_wait_list we may wait.
    struct pkt_wait_list *sync_with;
};

/// Construct a pkt_wait_list
int pkt_wait_list_ctor(
    struct pkt_wait_list *pkt_wl,   ///< The waiting list to construct
    unsigned next_offset,           ///< The initial offset we are waiting for
    struct pkt_wl_config *config,   ///< Where we store the pkt_wait_list created with these parameters (useful for timeouting) as well as global conf
    struct parser *parser,          ///< The parser that's supposed to parse this packet whenever possible
    /// If <> NULL, synchronize this pkt_wait_list with another one (ie. packets from this one may wait for the other waiting list to advance)
    struct pkt_wait_list *restrict sync_with
);

/// Destruct a pkt_wait_list, calling the subscribers for every pending packets.
void pkt_wait_list_dtor(struct pkt_wait_list *);

/// Enqueue a packet (or deal with it immediately if possible)
/** This function may call the subparser immediately if no waiting is required.
 * Also, it may call the continuation (skipping subparser) immediately if the
 * offset looks erroneous (ie. either in the past or too much in the future -
 * more than the defined acceptable gap).
 * Set can_parse to false if you want to prevent all call to subparser
 * (erroneous packets will still be "parsed", though).
 * If the parser fails it will be destroyed (unreferenced, rather, in both
 * directions). */
enum proto_parse_status pkt_wait_list_add(
    struct pkt_wait_list *pkt_wl,   ///< The packet list where to insert this packet
    unsigned offset,                ///< Offset in the stream of this packet
    unsigned next_offset,           ///< Offset in the stream of the following packet
    bool sync,                      ///< Set to false to disable syncing (even when wl->sync_with is set)
    unsigned sync_offset,           ///< If sync, do not parse until the other WL we sync with reach at least this point
    bool can_parse,                 ///< True if we are allowed to parse this packet (and others that were pending) if possible
    struct proto_info *parent,      ///< The proto_info of its parent (likely the caller of this function)
    unsigned way,                   ///< Direction identifier (see proto_parse())
    uint8_t const *packet,          ///< The origin packet
    size_t cap_len,                 ///< It's length
    size_t wire_len,                ///< It's actual length on the wire
    struct timeval const *now,      ///< The current time
    size_t tot_cap_len,             ///< The capture length of the whole packet
    uint8_t const *tot_packet       ///< The whole packet (as given to subscribers)
);

/// Try to parse (or timeout) the head of the list.
/** @return true if some parsing was done. */
bool pkt_wait_list_try(
    struct pkt_wait_list *pkt_wl,   ///< The packet list to try to advance
    enum proto_parse_status *status,///< An output parameter wihch will be set to last result of parsing or unset if no parsing took place
    struct timeval const *now,      ///< Current timestamp
    bool force_timeout              ///< Force consuming the first waiting packet
);

/// Same as above, but will consume the reciprocal waiting_list as well
bool pkt_wait_list_try_both(struct pkt_wait_list *pkt_wl, enum proto_parse_status *, struct timeval const *now, bool force_timeout);

/// Tells if the wait list is complete between these two offsets.
/** @note this checks weither all packets were received, not if enough bytes
 * were captured from them. */
bool pkt_wait_list_is_complete(struct pkt_wait_list *, unsigned start_offset, unsigned end_offset);

/// Return an objalloced buffer with the reassembled bytes
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
    size_t wire_len                 ///< It's actual length on the wire (if payload is set)
);

/// Removes a packet from a list, without calling the subparser.
void pkt_wait_del(struct pkt_wait *, struct pkt_wait_list *);

void pkt_wait_list_init(void);
void pkt_wait_list_fini(void);

#endif
