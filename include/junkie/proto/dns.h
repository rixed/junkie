// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef DNS_H_100511
#define DNS_H_100511

/** @file
 * @brief DNS informations
 */

#define DNS_PORT 53
#define NBNS_PORT 137
#define MDNS_PORT 5353
#define LLMNR_PORT 5355

extern struct proto *proto_dns;
extern struct proto *proto_dns_tcp;

enum dns_req_type {
    DNS_TYPE_UNSET = 0,
    DNS_TYPE_A = 0x0001,
    DNS_TYPE_NS, DNS_TYPE_MD, DNS_TYPE_MF, DNS_TYPE_CNAME,
    DNS_TYPE_SOA, DNS_TYPE_MB, DNS_TYPE_MG, DNS_TYPE_MR,
    DNS_TYPE_NULL, DNS_TYPE_WKS, DNS_TYPE_PTR, DNS_TYPE_HINFO,
    DNS_TYPE_MINFO, DNS_TYPE_MX, DNS_TYPE_TXT,
    DNS_TYPE_AAAA = 0x001c,
    DNS_TYPE_NBNS = 0x0020,
    DNS_TYPE_SRV = 0x0021, /* or DNS_TYPE_NBSTAT for NBNS protocol, ie port 137 */
    DNS_TYPE_A6 = 0x0026,
    DNS_TYPE_IXFR = 0x00fb,
    DNS_TYPE_AXFR = 0x00fc,
    DNS_TYPE_ANY = 0x00ff,
};

enum dns_class {
    DNS_CLASS_UNSET = 0,
    DNS_CLASS_IN = 1,
    DNS_CLASS_CS, DNS_CLASS_CH, DNS_CLASS_HS,
    DNS_CLASS_ANY = 255,
};

/// Description of a DNS message
struct dns_proto_info {
    struct proto_info info;         ///< Generic sizes
    bool query;                     ///< Set if the message is a query
    uint16_t transaction_id;        ///< TxId of the message
    uint16_t error_code;            ///< Error code
    enum dns_req_type request_type; ///< Request type of the message
    enum dns_class dns_class;       ///< Class of the message
    char name[255+1];               ///< Resolved name
};

void dns_init(void);
void dns_fini(void);

void dns_tcp_init(void);
void dns_tcp_fini(void);

#endif
