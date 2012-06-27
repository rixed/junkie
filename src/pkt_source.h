// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef PKT_SOURCE_H_101110
#define PKT_SOURCE_H_101110

#include <stdbool.h>
#include <limits.h>
#include <stdint.h>
#include <pcap.h>
#include <pthread.h>
#include "junkie/tools/queue.h"
#include "junkie/tools/mutex.h"
#include "junkie/proto/proto.h"

/** A Packet Source is something that gives us packets (with libpcap).
 * So basically it can be either a real interface or a file.
 */
struct pkt_source {
    LIST_ENTRY(pkt_source) entry;   ///< Entry in the list of all packet sources
    char name[PATH_MAX];            ///< The name to identify this source
    unsigned instance;              ///< If several pkt_source uses the same name (as is frequent), distinguish them with this
    pcap_t *pcap_handle;            ///< The handle for libpcap
    pthread_t sniffer;              ///< The thread sniffing this device or file
    uint64_t nb_packets;            ///< Number of packets received from PCAP
    uint64_t nb_duplicates;         ///< Number of which that were duplicates
    uint64_t nb_cap_bytes;          ///< Number of captured bytes from this source
    uint64_t nb_wire_bytes;         ///< Number of bytes on the wire for this source
    bool is_file;                   ///< A flag to distinguish between files and ifaces
    bool patch_ts;                  ///< If set, all frame timestamps will be overwritten with current time (only valid when is_file)
    bool loop;                      ///< If set, the pcap will be read in a loop (only valid when is_file)
    /** A numerical id used to distinguish various interfaces during parsing
        (same underlying interface will have same dev_id, while same pcap files will have distinct dev_id). */
    uint8_t dev_id;
    char *filter;                   ///< Packet filter expression in use for this device (for reference only)
};

/** Now the frame structure that will be given to the cap parser, since
 * in addition to pcap header it also need device identifier. */
struct frame {
    struct timeval tv;  ///< timestamp of frame reception
    size_t cap_len;     ///< number of bytes captured
    size_t wire_len;    ///< number of bytes on the wire
    struct pkt_source const *pkt_source;  ///< the pkt_source this packet was read from
    uint8_t /*const*/ *data;    ///< the packet itself (FIXME: fix digest_frame then restore const)
};

// Call every interrested parties
int parser_callbacks(struct proto_info const *last, size_t tot_cap_len, uint8_t const *tot_packet);

void pkt_source_init(void);
void pkt_source_fini(void);

#endif
