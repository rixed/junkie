// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2013, SecurActive.
 *
 * This file is part of Junkie.
 *
 * Junkie is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Junkie is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Junkie.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include "junkie/config.h"
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include "junkie/tools/objalloc.h"
#include "junkie/tools/miscmacs.h"
#include "junkie/tools/ip_addr.h"
#include "junkie/proto/streambuf.h"
#include "junkie/proto/port_muxer.h"
#include "junkie/proto/cursor.h"
#include "junkie/proto/tcp.h"
#include "junkie/proto/ip.h"
#include "junkie/proto/ber.h"
#include "junkie/proto/tls.h"

#undef LOG_CAT
#define LOG_CAT proto_tls_log_category

LOG_CATEGORY_DEF(proto_tls);

/*
 * Keyfiles Management
 */

struct tls_keyfile {
    LIST_ENTRY(tls_keyfile) entry;
    SSL_CTX *ssl_ctx;
    char path[PATH_MAX];
    char pwd[1024];
    struct ip_addr net, mask;
    struct proto *proto;
};

static LIST_HEAD(tls_keyfiles, tls_keyfile) tls_keyfiles;
static struct mutex tls_keyfiles_lock;

static int tls_password_cb(char *buf, int bufsz, int rwflag, void *keyfile_)
{
    struct tls_keyfile *keyfile = keyfile_;

    assert(0 == rwflag);
    int len = snprintf(buf, bufsz, "%s", keyfile->pwd);
    if (bufsz <= len) return 0;
    return len;
}

static int tls_keyfile_ctor(struct tls_keyfile *keyfile, char const *path, char const *pwd, struct ip_addr const *net, struct ip_addr const *mask, struct proto *proto)
{
    SLOG(LOG_DEBUG, "Construct keyfile@%p '%s' for '%s'", keyfile, path, ip_addr_2_str(net));

    // Initialize our only SSL_CTX, with a single private key, that we will use for everything
    keyfile->ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    if (! keyfile->ssl_ctx) {
        SLOG(LOG_ERR, "SSL error while initializing keyfile %s: %s", path, ERR_error_string(ERR_get_error(), NULL));
        goto err0;
    }
    // Load private key file TODO
    if (1 != SSL_CTX_use_PrivateKey_file(keyfile->ssl_ctx, path, SSL_FILETYPE_PEM)) {
        if (1 != SSL_CTX_use_PrivateKey_file(keyfile->ssl_ctx, path, SSL_FILETYPE_ASN1)) {
            SLOG(LOG_ERR, "Cannot load keyfile %s", path);
            goto err1;
        }
    }

    snprintf(keyfile->path, sizeof(keyfile->path), "%s", path);
    snprintf(keyfile->pwd, sizeof(keyfile->pwd), "%s", pwd ? pwd:"");
    // if we have a password:
    if (pwd) {
        SSL_CTX_set_default_passwd_cb(keyfile->ssl_ctx, tls_password_cb);
        SSL_CTX_set_default_passwd_cb_userdata(keyfile->ssl_ctx, keyfile);
    }
    keyfile->net = *net;
    keyfile->mask = *mask;
    keyfile->proto = proto;
    WITH_LOCK(&tls_keyfiles_lock) {
        LIST_INSERT_HEAD(&tls_keyfiles, keyfile, entry);
    }

    return 0;
err1:
    SSL_CTX_free(keyfile->ssl_ctx);
err0:
    return -1;
}

static struct tls_keyfile *tls_keyfile_new(char const *path, char const *pwd, struct ip_addr const *net, struct ip_addr const *mask, struct proto *proto)
{
    struct tls_keyfile *keyfile = objalloc(sizeof(*keyfile), "keyfiles");
    if (! keyfile) return NULL;
    if (0 != tls_keyfile_ctor(keyfile, path, pwd, net, mask, proto)) {
        objfree(keyfile);
        return NULL;
    }
    return keyfile;
}

static void tls_keyfile_dtor(struct tls_keyfile *keyfile)
{
    SLOG(LOG_DEBUG, "Destruct keyfile@%p '%s' for '%s'", keyfile, keyfile->path, ip_addr_2_str(&keyfile->net));

    WITH_LOCK(&tls_keyfiles_lock) {
        LIST_REMOVE(keyfile, entry);
    }
}

static void tls_keyfile_del(struct tls_keyfile *keyfile)
{
    tls_keyfile_dtor(keyfile);
    objfree(keyfile);
}

static struct tls_keyfile *tls_keyfile_of_name(char const *name)
{
    struct tls_keyfile *keyfile;
    WITH_LOCK(&tls_keyfiles_lock) {
        LIST_LOOKUP(keyfile, &tls_keyfiles, entry, 0 == strcmp(keyfile->path, name));
    }
    return keyfile;
}

static struct tls_keyfile *tls_keyfile_lookup(struct ip_addr const *ip, uint16_t unused_ port)
{
    struct tls_keyfile *keyfile;
    WITH_LOCK(&tls_keyfiles_lock) {
        LIST_LOOKUP(keyfile, &tls_keyfiles, entry, ip_addr_match_mask(ip, &keyfile->net, &keyfile->mask));
    }
    return keyfile;
}

static struct tls_keyfile *tls_keyfile_of_scm_name(SCM name_)
{
    char *name = scm_to_tempstr(name_);
    return tls_keyfile_of_name(name);
}

static struct ext_function sg_tls_keys;
static SCM g_tls_keys(void)
{
    SCM ret = SCM_EOL;
    struct tls_keyfile *keyfile;

    scm_dynwind_begin(0);
    mutex_lock(&tls_keyfiles_lock);
    scm_dynwind_unwind_handler(pthread_mutex_unlock_, &tls_keyfiles_lock.mutex, SCM_F_WIND_EXPLICITLY);

    LIST_FOREACH(keyfile, &tls_keyfiles, entry) {
        ret = scm_cons(scm_from_latin1_string(keyfile->path), ret);
    }
    scm_dynwind_end();

    return ret;
}

static struct ext_function sg_tls_add_key;
static SCM g_tls_add_key(SCM file_, SCM net_, SCM mask_, SCM proto_, SCM pwd_)
{
    (void)pwd_; // TODO

    char const *file = scm_to_tempstr(file_);
    struct ip_addr net, mask;
    if (0 != scm_netmask_2_ip_addr2(&net, &mask, net_, mask_)) return SCM_BOOL_F;
    struct proto *proto = proto_of_scm_name(proto_);
    if (! proto) return SCM_BOOL_F;

    struct tls_keyfile *keyfile = tls_keyfile_new(file, NULL, &net, &mask, proto);
    return keyfile ? SCM_BOOL_T : SCM_BOOL_F;
}

static struct ext_function sg_tls_del_key;
static SCM g_tls_del_key(SCM file_)
{
    struct tls_keyfile *keyfile = tls_keyfile_of_scm_name(file_);
    if (! keyfile) return SCM_BOOL_F;

    tls_keyfile_del(keyfile);
    return SCM_BOOL_T;
}


/*
 * TLS Protocol Parser
 */

static bool cipher_uses_rsa(enum tls_cipher_suite cipher)
{
    switch (cipher) {
        case TLS_RSA_WITH_NULL_MD5:
        case TLS_RSA_WITH_NULL_SHA:
        case TLS_RSA_EXPORT_WITH_RC4_40_MD5:
        case TLS_RSA_WITH_RC4_128_MD5:
        case TLS_RSA_WITH_RC4_128_SHA:
        case TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5:
        case TLS_RSA_WITH_IDEA_CBC_SHA:
        case TLS_RSA_EXPORT_WITH_DES40_CBC_SHA:
        case TLS_RSA_WITH_DES_CBC_SHA:
        case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
        case TLS_RSA_WITH_AES_128_CBC_SHA:
        case TLS_RSA_WITH_AES_256_CBC_SHA:
        case TLS_RSA_WITH_NULL_SHA256:
        case TLS_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_RSA_WITH_AES_256_CBC_SHA256:
            return true;
        default:
            return false;
    }
}

static bool rsa_cipher_is_ephemeral(enum tls_cipher_suite cipher)
{
    switch (cipher) {
        case TLS_RSA_EXPORT_WITH_RC4_40_MD5:
        case TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5:
        case TLS_RSA_EXPORT_WITH_DES40_CBC_SHA:
            return true;
        default:
            return false;
    }
}

static struct tls_cipher_info {
#define KEX_RSA     0x10
#define KEX_DH      0x11
#define SIG_RSA     0x20
#define SIG_DSS     0x21
#define SIG_NONE    0x22
#define ENC_DES     0x30
#define ENC_3DES    0x31
#define ENC_RC4     0x32
#define ENC_RC2     0x33
#define ENC_IDEA    0x34
#define ENC_AES128  0x35
#define ENC_AES256  0x36
#define ENC_NULL    0x37
#define DIG_MD5     0x40
#define DIG_SHA     0x41
    bool defined;
    EVP_CIPHER const *ciph;
    int kex;
    int sig;
    int enc;
    int block;
    int bits;
    int eff_bits;
    int dig;
    unsigned dig_len;
    int export;
} tls_cipher_infos[] = {
    [1] = { true, NULL, KEX_RSA,SIG_RSA,ENC_NULL,0,0,0,DIG_MD5,16,0 },
    [2] = { true, NULL, KEX_RSA,SIG_RSA,ENC_NULL,0,0,0,DIG_SHA,20,0 },
    [3] = { true, NULL, KEX_RSA,SIG_RSA,ENC_RC4,1,128,40,DIG_MD5,16,1 },
    [4] = { true, NULL, KEX_RSA,SIG_RSA,ENC_RC4,1,128,128,DIG_MD5,16,0 },
    [5] = { true, NULL, KEX_RSA,SIG_RSA,ENC_RC4,1,128,128,DIG_SHA,20,0 },
    [6] = { true, NULL, KEX_RSA,SIG_RSA,ENC_RC2,8,128,40,DIG_SHA,20,1 },
    [7] = { true, NULL, KEX_RSA,SIG_RSA,ENC_IDEA,8,128,128,DIG_SHA,20,0 },
    [8] = { true, NULL, KEX_RSA,SIG_RSA,ENC_DES,8,64,40,DIG_SHA,20,1 },
    [9] = { true, NULL, KEX_RSA,SIG_RSA,ENC_DES,8,64,64,DIG_SHA,20,0 },
    [10] = { true, NULL, KEX_RSA,SIG_RSA,ENC_3DES,8,192,192,DIG_SHA,20,0 },
    [11] = { true, NULL, KEX_DH,SIG_DSS,ENC_DES,8,64,40,DIG_SHA,20,1 },
    [12] = { true, NULL, KEX_DH,SIG_DSS,ENC_DES,8,64,64,DIG_SHA,20,0 },
    [13] = { true, NULL, KEX_DH,SIG_DSS,ENC_3DES,8,192,192,DIG_SHA,20,0 },
    [14] = { true, NULL, KEX_DH,SIG_RSA,ENC_DES,8,64,40,DIG_SHA,20,1 },
    [15] = { true, NULL, KEX_DH,SIG_RSA,ENC_DES,8,64,64,DIG_SHA,20,0 },
    [16] = { true, NULL, KEX_DH,SIG_RSA,ENC_3DES,8,192,192,DIG_SHA,20,0 },
    [17] = { true, NULL, KEX_DH,SIG_DSS,ENC_DES,8,64,40,DIG_SHA,20,1 },
    [18] = { true, NULL, KEX_DH,SIG_DSS,ENC_DES,8,64,64,DIG_SHA,20,0 },
    [19] = { true, NULL, KEX_DH,SIG_DSS,ENC_3DES,8,192,192,DIG_SHA,20,0 },
    [20] = { true, NULL, KEX_DH,SIG_RSA,ENC_DES,8,64,40,DIG_SHA,20,1 },
    [21] = { true, NULL, KEX_DH,SIG_RSA,ENC_DES,8,64,64,DIG_SHA,20,0 },
    [22] = { true, NULL, KEX_DH,SIG_RSA,ENC_3DES,8,192,192,DIG_SHA,20,0 },
    [23] = { true, NULL, KEX_DH,SIG_NONE,ENC_RC4,1,128,40,DIG_MD5,16,1 },
    [24] = { true, NULL, KEX_DH,SIG_NONE,ENC_RC4,1,128,128,DIG_MD5,16,0 },
    [25] = { true, NULL, KEX_DH,SIG_NONE,ENC_DES,8,64,40,DIG_MD5,16,1 },
    [26] = { true, NULL, KEX_DH,SIG_NONE,ENC_DES,8,64,64,DIG_MD5,16,0 },
    [27] = { true, NULL, KEX_DH,SIG_NONE,ENC_3DES,8,192,192,DIG_MD5,16,0 },
    [47] = { true, NULL, KEX_RSA,SIG_RSA,ENC_AES128,16,128,128,DIG_SHA,20,0 },
    [48] = { true, NULL, KEX_DH,SIG_DSS,ENC_AES128,16,128,128,DIG_SHA,20,0 },
    [49] = { true, NULL, KEX_DH,SIG_RSA,ENC_AES128,16,128,128,DIG_SHA,20,0 },
    [50] = { true, NULL, KEX_DH,SIG_DSS,ENC_AES128,16,128,128,DIG_SHA,20,0 },
    [51] = { true, NULL, KEX_DH,SIG_RSA,ENC_AES128,16,128,128,DIG_SHA,20,0 },
    [52] = { true, NULL, KEX_DH,SIG_NONE,ENC_AES128,16,128,128,DIG_SHA,20,0 },
    [53] = { true, NULL, KEX_RSA,SIG_RSA,ENC_AES256,16,256,256,DIG_SHA,20,0 },
    [54] = { true, NULL, KEX_DH,SIG_DSS,ENC_AES256,16,256,256,DIG_SHA,20,0 },
    [55] = { true, NULL, KEX_DH,SIG_RSA,ENC_AES256,16,256,256,DIG_SHA,20,0 },
    [56] = { true, NULL, KEX_DH,SIG_DSS,ENC_AES256,16,256,256,DIG_SHA,20,0 },
    [57] = { true, NULL, KEX_DH,SIG_RSA,ENC_AES256,16,256,256,DIG_SHA,20,0 },
    [58] = { true, NULL, KEX_DH,SIG_NONE,ENC_AES256,16,256,256,DIG_SHA,20,0 },
    [96] = { true, NULL, KEX_RSA,SIG_RSA,ENC_RC4,1,128,56,DIG_MD5,16,1 },
    [97] = { true, NULL, KEX_RSA,SIG_RSA,ENC_RC2,1,128,56,DIG_MD5,16,1 },
    [98] = { true, NULL, KEX_RSA,SIG_RSA,ENC_DES,8,64,64,DIG_SHA,20,1 },
    [99] = { true, NULL, KEX_DH,SIG_DSS,ENC_DES,8,64,64,DIG_SHA,20,1 },
    [100] = { true, NULL, KEX_RSA,SIG_RSA,ENC_RC4,1,128,56,DIG_SHA,20,1 },
    [101] = { true, NULL, KEX_DH,SIG_DSS,ENC_RC4,1,128,56,DIG_SHA,20,1 },
    [102] = { true, NULL, KEX_DH,SIG_DSS,ENC_RC4,1,128,128,DIG_SHA,20,0 },
};

static char const *cipher_name_of_enc(unsigned enc)
{
    switch (enc) {
        case ENC_DES: return "DES";
        case ENC_3DES: return "DES3";
        case ENC_RC4: return "RC4";
        case ENC_RC2: return "RC2";
        case ENC_IDEA: return "IDEA";
        case ENC_AES128: return "AES128";
        case ENC_AES256: return "AES256";
    }
    assert(!"Invalid encoder");
}

struct tls_parser {
    struct parser parser;
    unsigned c2s_way;       // The way when traffic is going from client to server (UNSET for unset)
    struct streambuf sbuf;
    // Cryptographic material (handle with care!)
    unsigned current[2];   // Tells which spec is in order for this direction. Never UNSET.
    struct tls_cipher_spec {
        enum tls_cipher_suite cipher;
        enum tls_compress_algo compress;
        struct tls_version version;
        uint8_t key_block[136];     // max required size
        bool decoder_ready;         // if true then decoders are inited
        struct tls_decoder {  // used for the establishment of next crypto keys
#           define RANDOM_LEN 32
            uint8_t random[RANDOM_LEN];
            // pointers into key_block
            uint8_t *mac_key, *write_key, *init_vector; // points into key_block
            EVP_CIPHER_CTX evp;
        } decoder[2];   // one for each direction
    } spec[2];   // current or next
    // If we manage to decrypt, then we handle content to this parser
    struct parser *subparser;
};


static parse_fun tls_sbuf_parse;
static int tls_parser_ctor(struct tls_parser *tls_parser, struct proto *proto)
{
    SLOG(LOG_DEBUG, "Constructing tls_parser@%p", tls_parser);
    assert(proto == proto_tls);
    if (0 != parser_ctor(&tls_parser->parser, proto)) return -1;
    tls_parser->c2s_way = UNSET;
    tls_parser->current[0] = tls_parser->current[1] = 0;
    tls_parser->spec[0].decoder_ready = tls_parser->spec[1].decoder_ready = false;
    tls_parser->spec[0].cipher = tls_parser->spec[1].cipher = TLS_NULL_WITH_NULL_NULL;
    tls_parser->subparser = NULL;
#   define MAX_TLS_BUFFER (16383 + 5)
    if (0 != streambuf_ctor(&tls_parser->sbuf, tls_sbuf_parse, MAX_TLS_BUFFER)) return -1;

    return 0;
}

static struct parser *tls_parser_new(struct proto *proto)
{
    struct tls_parser *tls_parser = objalloc_nice(sizeof(*tls_parser), "TLS parsers");
    if (! tls_parser) return NULL;

    if (-1 == tls_parser_ctor(tls_parser, proto)) {
        objfree(tls_parser);
        return NULL;
    }

    return &tls_parser->parser;
}

static void tls_parser_dtor(struct tls_parser *tls_parser)
{
    SLOG(LOG_DEBUG, "Destructing tls_parser@%p", tls_parser);

    if (tls_parser->subparser) {
        parser_unref(&tls_parser->subparser);
    }

    parser_dtor(&tls_parser->parser);
    streambuf_dtor(&tls_parser->sbuf);
    for (unsigned way = 0; way < 2; way++) {
        for (unsigned current = 0; current < 2; current ++) {
            if (! tls_parser->spec[way].decoder_ready) continue;
            EVP_CIPHER_CTX_cleanup(&tls_parser->spec[way].decoder[current].evp);
        }
    }
}

static void tls_parser_del(struct parser *parser)
{
    struct tls_parser *tls_parser = DOWNCAST(parser, parser, tls_parser);
    tls_parser_dtor(tls_parser);
    objfree(tls_parser);
}

/*
 * Serialization
 */

static void const *tls_info_addr(struct proto_info const *info_, size_t *size)
{
    struct tls_proto_info const *info = DOWNCAST(info_, info, tls_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *tls_content_type_2_str(enum tls_content_type ct)
{
    switch (ct) {
        case tls_change_cipher_spec:
            return "change_cipher_spec";
        case tls_alert:
            return "alert";
        case tls_handshake:
            return "handshake";
        case tls_application_data:
            return "data";
    }
    assert(!"Unknown TLS content type");
}

static char const *tls_cipher_suite_2_str(enum tls_cipher_suite c)
{
    switch (c) {
#       define CASE(x) case TLS_##x: return #x
        CASE(NULL_WITH_NULL_NULL);               CASE(RSA_WITH_NULL_MD5);
        CASE(RSA_WITH_NULL_SHA);                 CASE(RSA_EXPORT_WITH_RC4_40_MD5);
        CASE(RSA_WITH_RC4_128_MD5);              CASE(RSA_WITH_RC4_128_SHA);
        CASE(RSA_EXPORT_WITH_RC2_CBC_40_MD5);    CASE(RSA_WITH_IDEA_CBC_SHA);
        CASE(RSA_EXPORT_WITH_DES40_CBC_SHA);     CASE(RSA_WITH_DES_CBC_SHA);
        CASE(RSA_WITH_3DES_EDE_CBC_SHA);         CASE(DH_DSS_EXPORT_WITH_DES40_CBC_SHA);
        CASE(DH_DSS_WITH_DES_CBC_SHA);           CASE(DH_DSS_WITH_3DES_EDE_CBC_SHA);
        CASE(DH_RSA_EXPORT_WITH_DES40_CBC_SHA);  CASE(DH_RSA_WITH_DES_CBC_SHA);
        CASE(DH_RSA_WITH_3DES_EDE_CBC_SHA);      CASE(DHE_DSS_EXPORT_WITH_DES40_CBC_SHA);
        CASE(DHE_DSS_WITH_DES_CBC_SHA);          CASE(DHE_DSS_WITH_3DES_EDE_CBC_SHA);
        CASE(DHE_RSA_EXPORT_WITH_DES40_CBC_SHA); CASE(DHE_RSA_WITH_DES_CBC_SHA);
        CASE(DHE_RSA_WITH_3DES_EDE_CBC_SHA);     CASE(DH_anon_EXPORT_WITH_RC4_40_MD5);
        CASE(DH_anon_WITH_RC4_128_MD5);          CASE(DH_anon_EXPORT_WITH_DES40_CBC_SHA);
        CASE(DH_anon_WITH_DES_CBC_SHA);          CASE(DH_anon_WITH_3DES_EDE_CBC_SHA);
        CASE(RSA_WITH_AES_128_CBC_SHA);          CASE(DH_DSS_WITH_AES_128_CBC_SHA);
        CASE(DH_RSA_WITH_AES_128_CBC_SHA);       CASE(DHE_DSS_WITH_AES_128_CBC_SHA);
        CASE(DHE_RSA_WITH_AES_128_CBC_SHA);      CASE(DH_anon_WITH_AES_128_CBC_SHA);
        CASE(RSA_WITH_AES_256_CBC_SHA);          CASE(DH_DSS_WITH_AES_256_CBC_SHA);
        CASE(DH_RSA_WITH_AES_256_CBC_SHA);       CASE(DHE_DSS_WITH_AES_256_CBC_SHA);
        CASE(DHE_RSA_WITH_AES_256_CBC_SHA);      CASE(DH_anon_WITH_AES_256_CBC_SHA);
        CASE(RSA_WITH_NULL_SHA256);              CASE(RSA_WITH_AES_128_CBC_SHA256);
        CASE(RSA_WITH_AES_256_CBC_SHA256);       CASE(DH_DSS_WITH_AES_128_CBC_SHA256);
        CASE(DH_RSA_WITH_AES_128_CBC_SHA256);    CASE(DHE_DSS_WITH_AES_128_CBC_SHA256);
        CASE(DHE_RSA_WITH_AES_128_CBC_SHA256);   CASE(DH_DSS_WITH_AES_256_CBC_SHA256);
        CASE(DH_RSA_WITH_AES_256_CBC_SHA256);    CASE(DHE_DSS_WITH_AES_256_CBC_SHA256);
        CASE(DHE_RSA_WITH_AES_256_CBC_SHA256);   CASE(DH_anon_WITH_AES_128_CBC_SHA256);
        CASE(DH_anon_WITH_AES_256_CBC_SHA256);
#       undef CASE
    }
    return tempstr_printf("Unknown cipher suite 0x%x", c);
}

static char const *tls_compress_algo_2_str(enum tls_compress_algo c)
{
    switch (c) {
        case TLS_COMPRESS_NULL: return "none";
        case TLS_COMPRESS_DEFLATE: return "deflate";
    }
    return tempstr_printf("Unknown compression algorithm 0x%x", c);
}

static char const *tls_info_spec_2_str(struct tls_proto_info const *info)
{
    switch (info->content_type) {
        case tls_handshake:
            return tempstr_printf("%s%s%s%s%s%s",
                info->set_values & CIPHER_SUITE_SET ? ", cipher_suite=":"",
                info->set_values & CIPHER_SUITE_SET ? tls_cipher_suite_2_str(info->u.handshake.cipher_suite) : "",
                info->set_values & CIPHER_SUITE_SET ? ", compression_algo=":"",
                info->set_values & CIPHER_SUITE_SET ? tls_compress_algo_2_str(info->u.handshake.compress_algorithm) : "",
                info->set_values & SERVER_COMMON_NAME_SET ? ", CN=":"",
                info->set_values & SERVER_COMMON_NAME_SET ? info->u.handshake.server_common_name:"");
        default:
            return "";
    }
}

static char const *tls_info_2_str(struct proto_info const *info_)
{
    struct tls_proto_info const *info = DOWNCAST(info_, info, tls_proto_info);
    return tempstr_printf("%s, version=%"PRIu8".%"PRIu8", content-type=%s%s",
        proto_info_2_str(&info->info),
        info->version.maj, info->version.min,
        tls_content_type_2_str(info->content_type),
        tls_info_spec_2_str(info));
}

static void tls_serialize(struct proto_info const *info_, uint8_t **buf)
{
    struct tls_proto_info const *info = DOWNCAST(info_, info, tls_proto_info);
    proto_info_serialize(&info->info, buf);
}

static void tls_deserialize(struct proto_info *info_, uint8_t const **buf)
{
    struct tls_proto_info *info = DOWNCAST(info_, info, tls_proto_info);
    proto_info_deserialize(&info->info, buf);
}


/*
 * Parsing
 */

static bool check_version(uint8_t maj, uint8_t min)
{
    return maj <= 3 && min <= 10;   // TODO
}

static enum proto_parse_status skip_version(struct cursor *cur)
{
    uint8_t maj = cursor_read_u8(cur);
    uint8_t min = cursor_read_u8(cur);
    return check_version(maj, min) ? PROTO_OK : PROTO_PARSE_ERR;
}

static enum proto_parse_status skip_session(struct cursor *cur)
{
    if (cur->cap_len < 1) return PROTO_TOO_SHORT;
    uint8_t len = cursor_read_u8(cur);
    if (cur->cap_len < len) return PROTO_TOO_SHORT;
    cursor_drop(cur, len);
    return PROTO_OK;
}

#define SECRET_LEN 48

static int tls_P_hash(SSL unused_ *ssl, uint8_t const *restrict secret, size_t seed_len, uint8_t const *restrict seed, const EVP_MD *md, size_t out_len, uint8_t *restrict out)
{
    HMAC_CTX hm;

    unsigned char A[MAX(EVP_MAX_MD_SIZE, seed_len)];
    // A0 is the seed
    memcpy(A, seed, seed_len);
    unsigned A_len = seed_len;

    while (out_len) {
        // Compute A(n)
        HMAC_Init(&hm, secret, SECRET_LEN/2, md);
        HMAC_Update(&hm, A, A_len);
        HMAC_Final(&hm, A, &A_len);

        // Compute P_hash = HMAC(secret, A(n) + seed)
        HMAC_Init(&hm, secret, SECRET_LEN/2, md);
        HMAC_Update(&hm, A, A_len);
        HMAC_Update(&hm, seed, seed_len);
        unsigned char tmp[EVP_MAX_MD_SIZE]; // FIXME: apart for the last run we could write in out directly
        unsigned tmp_len = sizeof(tmp);
        HMAC_Final(&hm, tmp, &tmp_len);

        size_t const to_copy = MIN(out_len, tmp_len);
        memcpy(out, tmp, to_copy);
        out += to_copy;
        out_len -= to_copy;
    }

    HMAC_cleanup(&hm);

    return 0;
}

static int tls_prf(SSL *ssl, uint8_t *secret, char const *label, uint8_t const *restrict r1, uint8_t const *restrict r2, size_t out_len, uint8_t *restrict out)
{
    int const label_len = strlen(label);
    uint8_t seed[label_len + RANDOM_LEN + RANDOM_LEN];
    memcpy(seed, label, label_len);
    memcpy(seed + label_len, r1, RANDOM_LEN);
    memcpy(seed + label_len + RANDOM_LEN, r2, RANDOM_LEN);

    size_t const md5_out_len = MAX(out_len, 16);
    uint8_t md5_out[md5_out_len];
    size_t const sha_out_len = MAX(out_len, 20);
    uint8_t sha_out[sha_out_len];

    if (0 != tls_P_hash(ssl, secret,                sizeof(seed), seed, EVP_get_digestbyname("MD5"),  md5_out_len, md5_out)) return -1;
    if (0 != tls_P_hash(ssl, secret + SECRET_LEN/2, sizeof(seed), seed, EVP_get_digestbyname("SHA1"), sha_out_len, sha_out)) return -1;

    for (unsigned i=0; i < out_len; i++) out[i] = md5_out[i] ^ sha_out[i];

    return 0;
}

static int ssl3_prf(SSL unused_ *ssl, uint8_t *secret, char const *label, uint8_t const *restrict r1, uint8_t const *restrict r2, size_t out_len, uint8_t *restrict out)
{
    (void)secret; (void)label; (void)r1; (void)r2; (void)out_len; (void)out;
    // TODO
    return -1;
}

static bool is_tls(struct tls_version version)
{
    return version.maj == 3 && version.min >= 1;
}

static int prf(struct tls_version version, SSL *ssl, uint8_t *secret, char const *label, uint8_t const *restrict r1, uint8_t const *restrict r2, size_t out_len, uint8_t *restrict out)
{
    return (is_tls(version) ? tls_prf : ssl3_prf)(ssl, secret, label, r1, r2, out_len, out);
}

// decrypt the pre_master_secret using server's private key
// Note: we follow ssldump footpath from there!
static int decrypt_master_secret(struct tls_parser *parser, unsigned way, struct tls_proto_info const *info, size_t data_len, uint8_t const *data)
{
    int err = -1;

    // find the relevant keyfile
    ASSIGN_INFO_OPT(tcp, &info->info);
    if (! tcp) goto quit0;
    ASSIGN_INFO_OPT(ip, &tcp->info);
    if (! ip) goto quit0;
    struct tls_keyfile *keyfile = tls_keyfile_lookup(&ip->key.addr[1], tcp->key.port[1]);
    if (! keyfile) {
        SLOG(LOG_DEBUG, "No keyfile found for %s:%"PRIu16, ip_addr_2_str(&ip->key.addr[1]), tcp->key.port[1]);
        goto quit0;
    }
    SLOG(LOG_DEBUG, "Will decrypt MS using keyfile %s", keyfile->path);

    SSL *ssl = SSL_new(keyfile->ssl_ctx);
    if (! ssl) {
        SLOG(LOG_ERR, "Cannot create SSL from SSL_CTX: %s", ERR_error_string(ERR_get_error(), NULL));
        goto quit0;
    }
    EVP_PKEY *pk = SSL_get_privatekey(ssl);
    if (! pk) {
        SLOG(LOG_ERR, "Cannot get private key from SSL object: %s", ERR_error_string(ERR_get_error(), NULL));
        goto quit1;
    }
    if (pk->type != EVP_PKEY_RSA) {
        SLOG(LOG_ERR, "Private key is not a RSA key.");
        // oh, well
    }

    uint8_t pre_master_secret[SECRET_LEN];  //RSA_size(pk->pkey.rsa)];
    int const pms_len = RSA_private_decrypt(data_len, data, pre_master_secret, pk->pkey.rsa, RSA_PKCS1_PADDING);
    if (pms_len != sizeof(pre_master_secret)) {
        SLOG(LOG_ERR, "Cannot decode pre_master_secret!");
        goto quit1;
    }

    // check version
    uint8_t const pms_ver_maj = pre_master_secret[0];
    uint8_t const pms_ver_min = pre_master_secret[1];
    SLOG(LOG_DEBUG, "pre_shared_secret: version=%d.%d", pms_ver_maj, pms_ver_min);
    if (! check_version(pms_ver_maj, pms_ver_min)) goto quit1;
    SLOG_HEX(LOG_DEBUG, pre_master_secret+2, sizeof(pre_master_secret)-2);

    // derive the master_secret (FIXME: wait to be sure we have both random + this pre_shared_secret)
    struct tls_cipher_spec *next_spec = &parser->spec[!parser->current[way]];
    struct tls_decoder *next_decoder = &next_spec->decoder[way];
    struct tls_decoder *srv_next_decoder = &parser->spec[!parser->current[!way]].decoder[!way];

    uint8_t master_secret[SECRET_LEN];
    if (0 != prf(next_spec->version, ssl,
                 pre_master_secret, "master secret",
                 next_decoder->random,
                 srv_next_decoder->random,
                 sizeof(master_secret), master_secret))
        goto quit1;

    if (next_spec->cipher >= NB_ELEMS(tls_cipher_infos)) {
unknown_cipher:
        SLOG(LOG_DEBUG, "Don't know the caracteristics of cipher %s", tls_cipher_suite_2_str(next_spec->cipher));
        goto quit1;
    }
    struct tls_cipher_info const *cipher_info = tls_cipher_infos + next_spec->cipher;
    if (! cipher_info->defined) goto unknown_cipher;

    unsigned const needed =
        cipher_info->dig_len*2 +
        cipher_info->bits/4 +
        (cipher_info->block > 1 ? cipher_info->block*2 : 0);
    assert(needed <= sizeof(next_spec->key_block));

    if (0 != prf(next_spec->version, ssl,
                 master_secret, "key expansion",
                 srv_next_decoder->random,
                 next_decoder->random,
                 needed, next_spec->key_block))
        goto quit1;
    SLOG(LOG_DEBUG, "key_block:");
    SLOG_HEX(LOG_DEBUG, next_spec->key_block, needed);

    // Save cryptographic material from the key_block
    // TODO: handle export ciphers?
    uint8_t *ptr = next_spec->key_block;
    next_decoder->mac_key = ptr; ptr += cipher_info->dig_len;
    srv_next_decoder->mac_key = ptr; ptr += cipher_info->dig_len;
    next_decoder->write_key = ptr; ptr += cipher_info->eff_bits/8;
    srv_next_decoder->write_key = ptr; ptr += cipher_info->eff_bits/8;
    if (cipher_info->block > 1) {
        next_decoder->init_vector = ptr; ptr += cipher_info->block;
        srv_next_decoder->init_vector = ptr; ptr += cipher_info->block;
    }

    // prepare a cipher for both directions
    for (unsigned dir = 0; dir < 2; dir ++) {
        if (next_spec->decoder_ready) {
            EVP_CIPHER_CTX_cleanup(&next_spec->decoder[dir].evp);
        }
        EVP_CIPHER_CTX_init(&next_spec->decoder[dir].evp);
        EVP_CipherInit(&next_spec->decoder[dir].evp, cipher_info->ciph, next_spec->decoder[dir].write_key, next_spec->decoder[dir].init_vector, 0);
    }
    next_spec->decoder_ready = true;

    // Prepare a subparser (if we haven't one yet)
    if (! parser->subparser && keyfile->proto) {
        parser->subparser = keyfile->proto->ops->parser_new(keyfile->proto);
        if (! parser->subparser) {
            SLOG(LOG_DEBUG, "Cannot create TLS subparser for proto %s", keyfile->proto->name);
            goto quit1;
        }
    }

    err = 0;
quit1:
    SSL_free(ssl);
quit0:
    return err;
}

static enum proto_parse_status look_for_cname(struct cursor *cur, void *info_)
{
    struct tls_proto_info *info = info_;
    enum proto_parse_status status;
    if (PROTO_OK != (status = ber_enter(cur))) return status;  // enter the RelativeDistinguishedName
    if (PROTO_OK != (status = ber_enter(cur))) return status;  // enter the AttributeValueAssertion
    // Look for commonName (in DER)
    if (cur->cap_len < 5) return PROTO_TOO_SHORT;
    if (
        cur->head[0] == 0x6 && cur->head[1] == 0x3 && cur->head[2] == 0x55 &&
        cur->head[3] == 0x4 && cur->head[4] == 0x3
    ) {
        SLOG(LOG_DEBUG, "Found commonName!!");
        cursor_drop(cur, 5);
        if (PROTO_OK != (status = ber_decode_string(cur, sizeof(info->u.handshake.server_common_name), info->u.handshake.server_common_name))) return status;
        info->set_values |= SERVER_COMMON_NAME_SET;
    } else {
        // Not commonName
        if (PROTO_OK != (status = ber_skip(cur))) return status;
        if (PROTO_OK != (status = ber_skip(cur))) return status;
    }

    return PROTO_OK;
}

static enum proto_parse_status tls_parse_certificate(struct tls_proto_info *info, struct cursor *cur)
{
    enum proto_parse_status status;
    if (PROTO_OK != (status = ber_enter(cur))) return status; // enter the Certificate
    if (PROTO_OK != (status = ber_enter(cur))) return status; // enter the TBSCertificate
    if (PROTO_OK != (status = ber_skip_optional(cur, 0))) return status;  // skip the optional Version (tag 0)
    if (PROTO_OK != (status = ber_skip(cur))) return status;  // skip the serial number
    if (PROTO_OK != (status = ber_skip(cur))) return status;  // skip the signature
    if (PROTO_OK != (status = ber_skip(cur))) return status;  // skip the issuer
    if (PROTO_OK != (status = ber_skip(cur))) return status;  // skip the validity
    if (PROTO_OK != (status = ber_foreach(cur, look_for_cname, info))) return status; // iter over all RelativeDistinguishedName and look for the common name
    return PROTO_OK;
}

static enum proto_parse_status tls_parse_handshake(struct tls_parser *parser, unsigned way, struct tls_proto_info *info, struct cursor *cur, size_t wire_len)
{
    enum tls_handshake_type {
        tls_hello_request = 0, tls_client_hello, tls_server_hello,
        tls_certificate = 11, tls_server_key_exchange, tls_certificate_request,
        tls_server_hello_done, tls_certificate_verify, tls_client_key_exchange,
        tls_finished = 20,
    };

    if (cur->cap_len < 4) {
        if (wire_len >= 4) return PROTO_TOO_SHORT;
        return PROTO_PARSE_ERR;
    }
    enum tls_handshake_type type = cursor_read_u8(cur);
    unsigned length = cursor_read_u24n(cur);
    assert(wire_len >= 4);
    wire_len -= 4;
    if (wire_len < length) return PROTO_PARSE_ERR;

    // Use a transient cursor to save the starting position so we can skip the whole message once we are done
    struct cursor tcur = *cur;
    struct tls_cipher_spec *next_spec = &parser->spec[!parser->current[way]];
    struct tls_decoder *next_decoder = &next_spec->decoder[way];

    switch (type) {
        enum proto_parse_status err;
#       define VERSION_LENGTH 2
        case tls_client_hello:
            // fix c2s_way
            parser->c2s_way = way;
            // Save random
            if (tcur.cap_len < VERSION_LENGTH+RANDOM_LEN) return PROTO_TOO_SHORT;
            if ((err = skip_version(&tcur)) != PROTO_OK) return err;
            ASSERT_COMPILE(sizeof(next_decoder->random) == RANDOM_LEN);
            cursor_copy(&next_decoder->random, &tcur, RANDOM_LEN);
            break;    // done with this record
        case tls_server_hello:
            // fix c2s_way
            parser->c2s_way = !way;
            // Save random, selected cipher suite and compression algorithm
            if (tcur.cap_len < VERSION_LENGTH+RANDOM_LEN) return PROTO_TOO_SHORT;
            next_spec->version.maj = cursor_read_u8(&tcur);
            next_spec->version.min = cursor_read_u8(&tcur);
            if (! check_version(next_spec->version.maj, next_spec->version.min)) return PROTO_PARSE_ERR;
            ASSERT_COMPILE(sizeof(next_decoder->random) == RANDOM_LEN);
            cursor_copy(&next_decoder->random, &tcur, RANDOM_LEN);
            if ((err = skip_session(&tcur)) != PROTO_OK) return err;
            if (tcur.cap_len < 3) return PROTO_TOO_SHORT;
            next_spec->cipher = cursor_read_u16n(&tcur);
            next_spec->compress = cursor_read_u8(&tcur);
            // the user might want to know
            info->set_values |= CIPHER_SUITE_SET;
            info->u.handshake.cipher_suite = next_spec->cipher;
            info->u.handshake.compress_algorithm = next_spec->compress;
            break;
        case tls_certificate:   // where the server shows us his public key (we don't need it, though)
            // fix c2s_way
            parser->c2s_way = !way;
            // We are going to read the first certificate
            if (tcur.cap_len < 3) return PROTO_TOO_SHORT;
            unsigned cert_len = cursor_read_u24n(&tcur);    // length of all certificates
            if (cert_len > wire_len) return PROTO_PARSE_ERR;
            if (tcur.cap_len < 3) return PROTO_TOO_SHORT;
            cert_len = cursor_read_u24n(&tcur);    // length of the first certificate
            if (cert_len > wire_len) return PROTO_PARSE_ERR;
            struct cursor cert = tcur;
            cert.cap_len = MIN(cert.cap_len, cert_len);
            return tls_parse_certificate(info, &cert);    // parse only the first
        case tls_client_key_exchange:   // where the client sends us the pre master secret, niam niam!
            // fix c2s_way
            parser->c2s_way = way;
            while (cipher_uses_rsa(next_spec->cipher) && !rsa_cipher_is_ephemeral(next_spec->cipher)) {  // cipher should be set by now (FIXME: check this)
                if (tcur.cap_len < 2) return PROTO_TOO_SHORT;
                unsigned len = cursor_read_u16n(&tcur);
                if (tcur.cap_len < len) return PROTO_TOO_SHORT;

                if (0 != decrypt_master_secret(parser, way, info, len, tcur.head)) {
                    // too bad.
                }
                break;
            }
            break;
        case tls_server_key_exchange:
            // fix c2s_way
            parser->c2s_way = !way;
            break;
        // TODO: other cases to fix c2s way as well
        default:
            SLOG(LOG_DEBUG, "Skipping handshake message of type %u", type);
            break;
    }

    // Go to next message in this record
    if (wire_len == length) return PROTO_OK;    // we are done
    assert(wire_len > length);
    wire_len -= length;
    if (cur->cap_len < length) return PROTO_TOO_SHORT;
    cursor_drop(cur, length);

    return tls_parse_handshake(parser, way, info, cur, wire_len);
}

static enum proto_parse_status tls_parse_change_cipher_spec(struct tls_parser *parser, unsigned way, struct tls_proto_info unused_ *info, struct cursor *cur, size_t wire_len)
{
    // there can be only one message in this record, and its length must be 1
    if (wire_len != 1) {
invalid:
        SLOG(LOG_DEBUG, "Invalid ChangeCipherSpec msg");
        return PROTO_PARSE_ERR;
    }
    // it's value is supposed to be 1
    if (cur->cap_len >= 1 && cur->head[0] != 1) goto invalid;

    // put next crypto material into production
    parser->current[way] ^= 1;
    SLOG(LOG_DEBUG, "Put in production new decoder (%sset)", parser->spec[parser->current[way]].decoder_ready ? "":"un");

    return PROTO_OK;
}

static enum proto_parse_status tls_parse_alert(struct tls_parser *parser, unsigned way, struct tls_proto_info *info, struct cursor *cur, size_t wire_len)
{
    (void)parser; (void)info; (void)cur; (void)wire_len; (void)way;
    return PROTO_OK;
}

static enum proto_parse_status tls_parse_application_data(struct tls_parser *parser, unsigned way, struct tls_proto_info *info, struct cursor *cur, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    // move this into payload
    assert(info->info.head_len > wire_len); // since we wait until a full record is there
    info->info.head_len -= wire_len;
    info->info.payload += wire_len;

    if (! parser->subparser) return PROTO_OK;

    enum proto_parse_status err = proto_parse(parser->subparser, &info->info, way, cur->head, cur->cap_len, wire_len, now, tot_cap_len, tot_packet);
    if (err != PROTO_OK) {
        parser_unref(&parser->subparser);
    }

    return PROTO_OK;
}

// Decrypt a whole record in one go
static int tls_decrypt(struct tls_cipher_spec *spec, unsigned way, size_t cap_len, size_t wire_len, unsigned char const *payload, size_t *out_sz, unsigned char *out)
{
    if (! spec->decoder_ready) {
        SLOG(LOG_DEBUG, "Cannot decrypt: decoder not ready");
        return -1;
    }

    struct tls_cipher_info const *cipher_info = tls_cipher_infos + spec->cipher;
    if (! cipher_info->defined) {
        SLOG(LOG_DEBUG, "Don't know this cipher (%s)", tls_cipher_suite_2_str(spec->cipher));
        return -1;
    }

    if (1 != EVP_Cipher(&spec->decoder[way].evp, out, payload, cap_len)) {
        if (cap_len == wire_len) {
            SLOG(LOG_DEBUG, "Failed to decrypt record");
            return -1;
        }
        // Otherwise this is understandable. Let's proceed then.
    }

    *out_sz = cap_len;

    if (cap_len != wire_len) {
        // We do not strip anything then, so that our subparser has a chance to read the beginning.
        return 0;
    }

    // Strip off the padding
    if (cipher_info->block > 1) {
        assert(cap_len > 0);
        uint8_t pad_len = out[cap_len - 1];
        if (pad_len > cap_len) {
            SLOG(LOG_DEBUG, "Invalid padding length (%"PRIu8" > %zu)", pad_len, cap_len);
            return -1;
        }
        *out_sz -= pad_len + 1;
    }

    // Strip off the MAC
    if (cipher_info->dig_len > *out_sz) {
        SLOG(LOG_DEBUG, "Cannot decrypt: no space for a MAC?");
        return -1;
    }
    *out_sz -= cipher_info->dig_len;

    SLOG(LOG_INFO, "Successfuly decrypted %zu bytes!", *out_sz);
    SLOG_HEX(LOG_INFO, out, *out_sz);

    return 0;
}

static enum proto_parse_status tls_parse_record(struct tls_parser *parser, unsigned way, struct tls_proto_info *info, size_t cap_len, size_t wire_len, uint8_t const *payload, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct tls_cipher_spec *spec = &parser->spec[parser->current[way]];
    bool const is_crypted = spec->cipher != TLS_NULL_WITH_NULL_NULL;
    struct cursor cur;

    if (is_crypted) {
        unsigned char *decrypted = alloca(wire_len);
        size_t size_out = wire_len;
        if (0 != tls_decrypt(spec, way, cap_len, wire_len, payload, &size_out, decrypted)) return PROTO_OK;    // more luck next record?
        assert(size_out < wire_len);
        wire_len = size_out;
        cursor_ctor(&cur, decrypted, size_out);
    } else {
        cursor_ctor(&cur, payload, cap_len);
    }

    switch (info->content_type) {
        case tls_handshake:
            return tls_parse_handshake(parser, way, info, &cur, wire_len);
        case tls_change_cipher_spec:
            return tls_parse_change_cipher_spec(parser, way, info, &cur, wire_len);
        case tls_alert:
            return tls_parse_alert(parser, way, info, &cur, wire_len);
        case tls_application_data:
            return tls_parse_application_data(parser, way, info, &cur, wire_len, now, tot_cap_len, tot_packet);
    }
    SLOG(LOG_DEBUG, "Unknown content_type");
    return PROTO_PARSE_ERR;
}

static enum proto_parse_status tls_sbuf_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct tls_parser *tls_parser = DOWNCAST(parser, parser, tls_parser);

    // If this is the first time we are called, init c2s_way
    if (tls_parser->c2s_way == UNSET) {
        tls_parser->c2s_way = !way;
        SLOG(LOG_DEBUG, "First packet, init c2s_way to %u", tls_parser->c2s_way);
    }

    // Wait for a full record before proceeding
#   define TLS_RECORD_HEAD 5
    if (wire_len < TLS_RECORD_HEAD) {
restart_record:
        streambuf_set_restart(&tls_parser->sbuf, way, payload, true);
        return PROTO_OK;
    }
    if (cap_len < TLS_RECORD_HEAD) return PROTO_TOO_SHORT;

    enum tls_content_type content_type = READ_U8(payload);
    unsigned proto_version_maj = READ_U8(payload+1);
    unsigned proto_version_min = READ_U8(payload+2);
    unsigned length = READ_U16N(payload+3);

    // Sanity checks
    if (proto_version_maj > 3 || content_type < tls_change_cipher_spec || content_type > tls_application_data) {
        SLOG(LOG_DEBUG, "Don't look like TLS");
        return PROTO_PARSE_ERR;
    }

    if (wire_len < TLS_RECORD_HEAD + length) goto restart_record;

    // Now build the proto_info
    struct tls_proto_info info;
    /* application_data parser will remove bytes from headers into payload, so that
     * only application data is counted as payload. */
    proto_info_ctor(&info.info, parser, parent, TLS_RECORD_HEAD + length, 0);
    info.version.maj = proto_version_maj;
    info.version.min = proto_version_min;
    info.content_type = content_type;
    info.set_values = 0;

    // Parse the rest of the record according to the content_type
    streambuf_set_restart(&tls_parser->sbuf, way, payload + TLS_RECORD_HEAD + length, false);

    enum proto_parse_status status = tls_parse_record(tls_parser, way, &info, MIN(cap_len - TLS_RECORD_HEAD, length), length, payload + TLS_RECORD_HEAD, now, tot_cap_len, tot_packet);

    if (status != PROTO_OK) return PROTO_PARSE_ERR;

    return proto_parse(NULL, &info.info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
}


static enum proto_parse_status tls_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct tls_parser *tls_parser = DOWNCAST(parser, parser, tls_parser);

    enum proto_parse_status const status = streambuf_add(&tls_parser->sbuf, parser, parent, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);

    return status;
}

/*
 * Initialization
 */

static struct proto proto_tls_;
struct proto *proto_tls = &proto_tls_;
static struct port_muxer tcp_port_muxer_https;
static struct port_muxer tcp_port_muxer_skinny;

void tls_init(void)
{
    log_category_proto_tls_init();

    LIST_INIT(&tls_keyfiles);
    mutex_ctor(&tls_keyfiles_lock, "TLS keyfiles");

    X509V3_add_standard_extensions();   // ssldump does this

    // Initialize all ciphers
    for (unsigned c = 0; c < NB_ELEMS(tls_cipher_infos); c++) {
        struct tls_cipher_info *info = tls_cipher_infos+c;
        if (! info->defined) continue;
        info->ciph = info->enc == ENC_NULL ?
            EVP_enc_null() : EVP_get_cipherbyname(cipher_name_of_enc(info->enc));
    }

    static struct proto_ops const ops = {
        .parse       = tls_parse,
        .parser_new  = tls_parser_new,
        .parser_del  = tls_parser_del,
        .info_2_str  = tls_info_2_str,
        .info_addr   = tls_info_addr,
        .serialize   = tls_serialize,
        .deserialize = tls_deserialize,
    };
    proto_ctor(&proto_tls_, &ops, "TLS", PROTO_CODE_TLS);
    port_muxer_ctor(&tcp_port_muxer_https, &tcp_port_muxers, 443, 443, proto_tls);
    port_muxer_ctor(&tcp_port_muxer_skinny, &tcp_port_muxers, 2443, 2443, proto_tls);

    // Extension functions to add keyfiles
    ext_function_ctor(&sg_tls_keys,
        "tls-keys", 0, 0, 0, g_tls_keys,
        "(tls-keys): returns a list of all known private keys.\n");

    ext_function_ctor(&sg_tls_add_key,
        "tls-add-key", 4, 1, 0, g_tls_add_key,
        "(tls-add-key \"/var/keys/secret.pem\" \"192.168.1.42\" \"255.255.255.255\" \"http\"): use this key to decrypt HTTP traffic to this IP.\n"
        "Optionally, you can pass a password (used to decrypt the file) as another argument.\n"
        "See also (? 'tls-del-key)\n");

    ext_function_ctor(&sg_tls_del_key,
        "tls-del-key", 1, 0, 0, g_tls_del_key,
        "(tls-del-key \"/var/keys/secret.pem\"): forget about this key.\n"
        "See also (? 'tls-add-key)\n");
}

void tls_fini(void)
{
    port_muxer_dtor(&tcp_port_muxer_skinny, &tcp_port_muxers);
    port_muxer_dtor(&tcp_port_muxer_https, &tcp_port_muxers);

    proto_dtor(&proto_tls_);

    struct tls_keyfile *keyfile;
    while (NULL != (keyfile = LIST_FIRST(&tls_keyfiles))) {
        tls_keyfile_del(keyfile);
    }
    mutex_dtor(&tls_keyfiles_lock);

    log_category_proto_tls_fini();
}
