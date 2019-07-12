// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef SIP_H_101221
#define SIP_H_101221
#include <junkie/proto/proto.h>
#include <junkie/tools/ip_addr.h>

/** @file
 * @brief SIP informations
 */

extern struct proto *proto_sip;

#define ID_MAXLEN 128

enum sip_cmd_e {
    SIP_CMD_REGISTER,
    SIP_CMD_INVITE,
    SIP_CMD_ACK,
    SIP_CMD_CANCEL,
    SIP_CMD_OPTIONS,
    SIP_CMD_BYE,
};

struct sip_proto_info {
    struct proto_info info;

#   define SIP_CMD_SET       0x001
#   define SIP_CSEQ_SET      0x002
#   define SIP_CODE_SET      0x004
#   define SIP_MIME_SET      0x008
#   define SIP_LENGTH_SET    0x010
#   define SIP_FROM_SET      0x020
#   define SIP_TO_SET        0x040
#   define SIP_VIA_SET       0x080
#   define SIP_CALLID_SET    0x100
#   define SIP_SESSIONID_SET 0x200
    uint32_t set_values;

    enum sip_cmd_e cmd;

    char from[128];
    char to[128];
#   define SIP_CALLID_LEN 128
    char call_id[SIP_CALLID_LEN+1];
#   define SIP_SESSIONID_LEN 32  // By RFC 7329
    char session_id[SIP_SESSIONID_LEN+1];
    char mime_type[128];
    struct sip_via {
        unsigned protocol;
        struct ip_addr addr;
        uint16_t port;
    } via;
    unsigned content_length;
    unsigned code;
    unsigned long cseq;
};

char const *sip_cmd_2_str(enum sip_cmd_e);

void sip_init(void);
void sip_fini(void);

#endif
