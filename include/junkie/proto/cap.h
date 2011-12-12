// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef CAP_H_100409
#define CAP_H_100409
#include <stdbool.h>
#include <junkie/tools/timeval.h>
#include <junkie/proto/proto.h>

/** @file
 * @brief Capture protocol.
 *
 * Capture is not am actual protocol, but gives information about the data
 * that was received from the packet capture engine (aka libpcap), such as
 * packet timestamp and incoming device.
 */

extern struct proto *proto_cap;

/// Description of the captured packet
struct cap_proto_info {
    struct proto_info info; ///< Header size is the size of our struct frame while payload corresponds to the total wire size
    unsigned dev_id;        ///< Incomming device id
    struct timeval tv;      ///< Date of arrival
};

bool collapse_ifaces;

void cap_init(void);
void cap_fini(void);

#endif
