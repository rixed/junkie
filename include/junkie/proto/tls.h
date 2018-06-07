// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef TLS_H_130325
#define TLS_H_130325
#include <stdint.h>
#include <junkie/proto/proto.h>
#include <junkie/proto/ber.h>

/** @file
 * @brief TLS informations
 */

extern struct proto *proto_tls;

enum tls_cipher_suite {
    TLS_NULL_WITH_NULL_NULL,                    // 0x000
    TLS_RSA_WITH_NULL_MD5,
    TLS_RSA_WITH_NULL_SHA,
    TLS_RSA_EXPORT_WITH_RC4_40_MD5,
    TLS_RSA_WITH_RC4_128_MD5,
    TLS_RSA_WITH_RC4_128_SHA,
    TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
    TLS_RSA_WITH_IDEA_CBC_SHA,
    TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,          // 0x008
    TLS_RSA_WITH_DES_CBC_SHA,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,
    TLS_DH_DSS_WITH_DES_CBC_SHA,
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
    TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
    TLS_DH_RSA_WITH_DES_CBC_SHA,
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,           // 0x010
    TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
    TLS_DHE_DSS_WITH_DES_CBC_SHA,
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
    TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
    TLS_DHE_RSA_WITH_DES_CBC_SHA,
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
    TLS_DH_anon_WITH_RC4_128_MD5,               // 0x018
    TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA,
    TLS_DH_anon_WITH_DES_CBC_SHA,
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,          // 0x01B

    TLS_RSA_WITH_AES_128_CBC_SHA = 0x02F,       // 0x02F
    TLS_DH_DSS_WITH_AES_128_CBC_SHA,            // 0x030
    TLS_DH_RSA_WITH_AES_128_CBC_SHA,
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_DH_anon_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    TLS_DH_DSS_WITH_AES_256_CBC_SHA,
    TLS_DH_RSA_WITH_AES_256_CBC_SHA,
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA,           // 0x038
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_DH_anon_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_NULL_SHA256,
    TLS_RSA_WITH_AES_128_CBC_SHA256,
    TLS_RSA_WITH_AES_256_CBC_SHA256,
    TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
    TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,        // 0x040
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA,
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA,
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA,

    // 0x062 to 0x066 -> Cf. Rescorla book p73+74 about non standard additions by [Banes1999]
    TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA = 0x062,
    TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA,
    TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,
    TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA,
    TLS_DHE_DSS_WITH_RC4_128_SHA,

    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x067,
    TLS_DH_DSS_WITH_AES_256_CBC_SHA256,         // 0x068
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
    TLS_DH_anon_WITH_AES_128_CBC_SHA256,
    TLS_DH_anon_WITH_AES_256_CBC_SHA256,        // 0x06D

    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x084,
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA,
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA,
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA,

    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x0BA,
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,       // 0x0C0
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256,
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256,
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256,
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256,
};

enum tls_compress_algo {
    TLS_COMPRESS_NULL,
    TLS_COMPRESS_DEFLATE,
};

struct tls_cert_info {
    /* Certificate users MUST be able to handle serialNumber values
     * up to 20 octets.  Conforming CAs MUST NOT use serialNumber
     * values longer than 20 octets. -- RFC 5280 */
    struct ber_uint serial_number;
#   define SIZEOF_SUBJECT 150
    char subject[SIZEOF_SUBJECT];
    char issuer[SIZEOF_SUBJECT];
    struct ber_time not_before, not_after;
};

char const *tls_cert_info_2_str(struct tls_cert_info const *, unsigned);

struct tls_proto_info {
    struct proto_info info;
    struct tls_version {
        uint8_t maj, min;
    } version;
    enum tls_content_type {
        tls_change_cipher_spec = 20, tls_alert, tls_handshake, tls_application_data,
    } content_type;
    // depending on the content_type:
    unsigned set_values;
    union {
        struct tls_info_handshake {
#           define CIPHER_SUITE_SET  0x1
            enum tls_cipher_suite cipher_suite;
            enum tls_compress_algo compress_algorithm;    // set whenever CIPHER_SUITE_SET is set
#           define NB_CERTS_SET  0x2
            uint8_t nb_certs;       // BEWARE: can be more than NB_ELEMS(cert);
            struct tls_cert_info certs[4];
#           define SERVER_NAME_INDICATION_SET 0x4
            char sni[64];
        } handshake;
    } u;
};

void tls_init(void);
void tls_fini(void);

#endif
