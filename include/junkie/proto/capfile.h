// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef CAPFILE_H_110124
#define CAPFILE_H_110124
#include <stdlib.h>
#include <junkie/tools/queue.h>
#include <junkie/tools/mutex.h>
#include <junkie/proto/proto.h>

/** @file
 * @brief Packet capture
 *
 * We want to be able to save a selected portion of all listened packets either
 * in a pcap file or in a CSV file.
 */

struct capfile {
    struct capfile_ops {
        int (*open)(struct capfile *, char const *path, struct timeval const *now);
        void (*close)(struct capfile *);
        int (*write)(struct capfile *, struct proto_info const *, size_t cap_len, uint8_t const *, struct timeval const *now);
        void (*del)(struct capfile *);
    } const *ops;
    LIST_ENTRY(capfile) entry;
    char *path;         // we will add an optional suffix to get actual path passed to the open() ops.
    unsigned max_pkts;
    size_t max_size;
    unsigned max_secs;
    size_t cap_len;
    unsigned rotation;
    unsigned file_num;  // this file number (if rotation)
    unsigned nb_pkts;   // number of packets written in this file
    size_t file_size;   // total number of bytes written in this file (including all sort of headers)
    struct timeval start;   // when we opened the file
    int fd;
    struct mutex lock;  // to avoid two threads to write simultaneously
};

/** start a new capture (in pcap) */
struct capfile *capfile_new_pcap(
    char const *path,   ///< The file to write to (will be truncated)
    unsigned max_pkts,  ///< If >0 then stop the capture after this amount of packets
    size_t max_size,    ///< If >0 then stop the capture after this file size
    unsigned max_secs,  ///< If >0 then stop the capture after this time
    size_t cap_len,     ///< If >0 then limit the packet size to this
    unsigned rotation,  ///< If >0 then a numeric prefix will be appended to file names and when a file is stopped a new file will be created, up to this number then wrap
    struct timeval const *now  ///< Start time of the file
);

struct capfile *capfile_new_csv(char const *path, unsigned max_pkts, size_t max_size, unsigned max_secs, size_t caplen, unsigned rotation, struct timeval const *start);
char *capfile_csv_from_info(struct proto_info const *);

void capfile_init(void);
void capfile_fini(void);

#endif
