// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef OS_DETECT_H_120411
#define OS_DETECT_H_120411
#include <junkie/proto/ip.h>
#include <junkie/proto/tcp.h>
/** @file
 * @brief Operating System Detection
 *
 * This function can detect the operating system used by the emmiter of the given
 * TCP SYN or SYN+ACK.
 *
 * It is automatically generated from p0f.fp database of signatures, and should be quite fast.
 */

/** @return an id identifying the OS, or 0 if unknown. */
unsigned os_detect(struct ip_proto_info const *ip, struct tcp_proto_info const *tcp);

/** @return the name associated with the above id. */
char const *os_name(unsigned id);

// Dummy function called by junkie init code so that the linker include this unused (as far as the linker can tell) unit
void os_detect_init(void);

#endif
