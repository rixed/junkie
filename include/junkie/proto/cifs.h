// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef CIFS_H_101221
#define CIFS_H_101221
#include <junkie/proto/proto.h>

/** @file
 * @brief CIFS informations
 */

extern struct proto *proto_cifs;

struct cifs_hdr {
    uint32_t code;
    uint8_t  command;
    uint32_t status;

    // flags
    unsigned request:1;
    unsigned notify:1;
    unsigned oplocks:1;
    unsigned canonicalized:1;
    unsigned case_sensitivity:1;
    unsigned receive_buffer_posted:1;
    unsigned lock_and_read:1;

    // flags 2

    unsigned unicode:1;
    unsigned error_code_type:1;
    unsigned execute_only_reads:1;
    unsigned dfs:1;
    unsigned reparse_path:1;
    unsigned long_names:1;
    unsigned security_signatures_required:1;
    unsigned compressed:1;
    unsigned extended_attributes:1;
    unsigned long_names_allowed:1;

    uint16_t process_id_high;
    uint64_t signature;
    uint16_t reserved;
    uint16_t tree_id;
    uint16_t process_id;
    uint16_t user_id;
    uint16_t multiplex_id;
} packed_;

struct cifs_proto_info {
    struct proto_info info;
    unsigned command;
    uint32_t status;
};

void cifs_init(void);
void cifs_fini(void);

#endif
