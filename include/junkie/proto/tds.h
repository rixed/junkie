// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef TDS_H_131107
#define TDS_H_131107
#include <stdint.h>
#include <stdbool.h>
#include <junkie/proto/proto.h>

extern LOG_CATEGORY_DEC(proto_tds);

/** @file
 * @brief TDS "transport" protocol
 */

extern struct proto *proto_tds;

/// Description of a tds packet
struct tds_proto_info {
    struct proto_info info;             ///< Generic infos
    enum tds_packet_type {
        TDS_PKT_TYPE_SQL_BATCH = 1,
        TDS_PKT_TYPE_LOGIN,
        TDS_PKT_TYPE_RPC,
        TDS_PKT_TYPE_RESULT,
        TDS_PKT_TYPE_ATTENTION = 6,
        TDS_PKT_TYPE_BULK_LOAD,
        TDS_PKT_TYPE_MANAGER_REQ = 14,
        TDS_PKT_TYPE_TDS7_LOGIN = 16,
        TDS_PKT_TYPE_SSPI,
        TDS_PKT_TYPE_PRELOGIN,
    } type;
#   define TDS_EOM                0x01
#   define TDS_IGNORE             0x02
#   define TDS_EVENT_NOTIF        0x04 // when is this used??
#   define TDS_RESET_CNX          0x08
#   define TDS_RESET_CNX_KEEP_TRX 0x10
    uint8_t status;
};

char const *tds_info_2_str(struct proto_info const *);
void const *tds_info_addr(struct proto_info const *, size_t *);

char const *tds_packet_type_2_str(enum tds_packet_type);

void tds_init(void);
void tds_fini(void);

#endif
