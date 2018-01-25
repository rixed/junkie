// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef GTP_H_180123
#define GTP_H_180123
#include <junkie/proto/proto.h>

/** @file
 * @brief GTP informations
 */

extern struct proto *proto_gtp;

enum gtp_msg_type {
#   define RR(name, n) \
    GTP_##name##_REQ = n, \
    GTP_##name##_RESP = (n+1)

    RR(ECHO, 1),
    GTP_VERSION_NOT_SUPPORTED = 3,
    RR(NODE_ALIVE, 4),
    RR(REDIRECTION, 6),
    RR(CREATE_PDP_CONTEXT, 16),
    RR(UPDATE_PDP_CONTEXT, 18),
    RR(DELETE_PDP_CONTEXT, 20),
    RR(INITIATE_PDP_CONTEXT_ACTIV, 22),
    GTP_ERROR_INDIC = 26,
    RR(PDU_NOTIF, 27),
    RR(PDU_NOTIF_REJECT, 29),
    GTP_SUPPORTED_EXTENSIONS_NOTIF = 31,
    RR(SEND_ROUTING_INFO, 32),
    RR(FAILURE_REPORT, 34),
    RR(MS_PRESENT, 36),
    RR(IDENTIFICATION, 48),
    RR(SGSN_CONTEXT, 50),
    GTP_SGSN_CONTEXT_ACK = 52,
    RR(FORWARD_RELOC, 53),
    GTP_FORWARD_RELOC_COMPLETE = 55,
    RR(RELOC_CANCEL, 56),
    GTP_FORWARD_SRNS_CONTEXT = 58,
    GTP_FORWARD_RELOC_COMPLETE_ACK = 59,
    GTP_FORWARD_SRNS_CONTEXT_ACK = 60,
    RR(UE_REGISTRATION_QUERY, 61),
    GTP_RAN_INFO_RELAY = 70,
    RR(MBMS_NOTIF, 96),
    RR(MBMS_NOTIF_REJECT, 98),
    RR(CREATE_MBMS_CONTEXT, 100),
    RR(UPDATE_MBMS_CONTEXT, 102),
    RR(DELETE_MBMS_CONTEXT, 104),
    RR(MBMS_REGISTRATION, 112),
    RR(MBMS_DEREGISTRATION, 114),
    RR(MBMS_SESSION_START, 116),
    RR(MBMS_SESSION_STOP, 118),
    RR(MBMS_SESSION_UPDATE, 120),
    RR(MS_INFO_CHG_NOTIF, 128),
    RR(DATA_RECORD_TRANSFERT, 240),
    // TODO: 3GPP TS 29.281 [41]
    GTP_END_MARKER = 254,
    GTP_GPDU = 255
};

/// GTP message
struct gtp_proto_info {
    struct proto_info info;
    enum gtp_msg_type msg_type;
#   define GTP_HAS_TEID        0x0001  // GTPv2 might have no TEID
#   define GTP_HAS_SEQNUM      0x0002
#   define GTP_HAS_NPDU_NUMBER 0x0004
    unsigned set_values;
    uint32_t teid;
    uint16_t seqnum;
    uint8_t version;
    uint8_t npdu_number;
};

void gtp_init(void);
void gtp_fini(void);

#endif
