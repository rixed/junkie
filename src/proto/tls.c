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
#include "junkie/tools/hash.h"
#include "junkie/proto/streambuf.h"
#include "junkie/proto/port_muxer.h"
#include "junkie/proto/cursor.h"
#include "junkie/proto/tcp.h"
#include "junkie/proto/ip.h"
#include "junkie/proto/ber.h"
#include "junkie/proto/tls.h"

// We use directly session_id digest as a hash key
#undef HASH_FUNC
#define HASH_FUNC(key) (*(key))

#undef LOG_CAT
#define LOG_CAT proto_tls_log_category

LOG_CATEGORY_DEF(proto_tls);

static unsigned max_sessions_per_key = 1000;
EXT_PARAM_RW(max_sessions_per_key, "tls-max-sessions-per-key", uint, "For each TLS key, remember only this number of sessions (keep the most recently used)")

/*
 * Errors
 */

char const *openssl_errors_2_str(void)
{
    char *str = tempstr();
    int len = 0;
    bool first = true;
    unsigned err;
    while (0 != (err = ERR_get_error()) && len < TEMPSTR_SIZE) {
        len += snprintf(str+len, TEMPSTR_SIZE-len, "%scode:0x%x:%s:%s:%s",
            first ? "":", ",
            err,
            ERR_lib_error_string(err),
            ERR_func_error_string(err),
            ERR_reason_error_string(err));
    }
    return str;
}

/*
 * Keyfiles & sessions Management
 */

struct tls_keyfile {
    LIST_ENTRY(tls_keyfile) entry;
    SSL_CTX *ssl_ctx;
    char path[PATH_MAX];
    char pwd[1024];
    struct ip_addr net, mask;
    bool is_mask;   // is false, then mask is actually the end of a range
    struct proto *proto;
    struct mutex lock;  // to protect the following lists
    HASH_TABLE(tls_sessions, tls_session) sessions; // index on session id and/or session tickets
    TAILQ_HEAD(tls_sessions_lru, tls_session) sessions_lru; // list of used sessions (ie. at least one of their hash is set)
};

static LIST_HEAD(tls_keyfiles, tls_keyfile) tls_keyfiles;
static struct mutex tls_keyfiles_lock;

struct tls_session {
    HASH_ENTRY(tls_session) h_entry_id; // only indexed if id_hash & KEY_HASH_SET
    HASH_ENTRY(tls_session) h_entry_ticket; // only indexed if ticket_hash & KEY_HASH_SET
#   define KEY_HASH_SET 0x80000000U // bit 31 used as a set flag
    uint32_t id_hash;
    uint32_t ticket_hash;
    TAILQ_ENTRY(tls_session) lru_entry; // only listed if id_hash & KEY_HASH_SET or ticket_hash & KEY_HASH_SET
#   define SECRET_LEN 48
    uint8_t master_secret[SECRET_LEN];
};

static uint32_t tls_session_key_hash(uint8_t id_len, uint8_t const *id)
{
    return hashfun(id, id_len);
}

static void tls_session_dtor(struct tls_session *session, struct tls_keyfile *keyfile)
{
    SLOG(LOG_DEBUG, "Destruct TLS session@%p", session);
    WITH_LOCK(&keyfile->lock) {
        if ((session->id_hash | session->ticket_hash) & KEY_HASH_SET) {
            TAILQ_REMOVE(&keyfile->sessions_lru, session, lru_entry);
        }
        if (session->id_hash & KEY_HASH_SET) {
            HASH_REMOVE(&keyfile->sessions, session, h_entry_id);
        }
        if (session->ticket_hash & KEY_HASH_SET) {
            HASH_REMOVE(&keyfile->sessions, session, h_entry_ticket);
        }
    }
}

static void tls_session_del(struct tls_session *session, struct tls_keyfile *keyfile)
{
    tls_session_dtor(session, keyfile);
    objfree(session);
}

static void tls_session_ctor(struct tls_session *session, struct tls_keyfile *keyfile, uint32_t id_hash, uint32_t ticket_hash, uint8_t const *master_secret)
{
    SLOG(LOG_DEBUG, "Constructing TLS session@%p for ", session);
    session->id_hash = id_hash;
    session->ticket_hash = ticket_hash;
    assert((session->id_hash | session->ticket_hash) & KEY_HASH_SET);
    memcpy(session->master_secret, master_secret, sizeof(session->master_secret));

    WITH_LOCK(&keyfile->lock) {
        while (HASH_SIZE(&keyfile->sessions) > max_sessions_per_key) {
            // remove least recently used session
            assert(TAILQ_LAST(&keyfile->sessions_lru, tls_sessions_lru));
            tls_session_del(TAILQ_LAST(&keyfile->sessions_lru, tls_sessions_lru), keyfile);
        }

        TAILQ_INSERT_HEAD(&keyfile->sessions_lru, session, lru_entry);

        if (session->id_hash & KEY_HASH_SET) {
            HASH_INSERT(&keyfile->sessions, session, &session->id_hash, h_entry_id);
        }
        if (session->ticket_hash & KEY_HASH_SET) {
            HASH_INSERT(&keyfile->sessions, session, &session->ticket_hash, h_entry_ticket);
        }
    }
}

static struct tls_session *tls_session_new(struct tls_keyfile *keyfile, uint32_t id_hash, uint32_t ticket_hash, uint8_t const *master_secret)
{
    struct tls_session *session = objalloc(sizeof(*session), "sessions");
    if (! session) return NULL;
    tls_session_ctor(session, keyfile, id_hash, ticket_hash, master_secret);
    return session;
}

static void tls_session_promote(struct tls_session *session, struct tls_keyfile *keyfile)
{
    TAILQ_REMOVE(&keyfile->sessions_lru, session, lru_entry);
    TAILQ_INSERT_HEAD(&keyfile->sessions_lru, session, lru_entry);
}

static int tls_password_cb(char *buf, int bufsz, int rwflag, void *keyfile_)
{
    struct tls_keyfile *keyfile = keyfile_;

    assert(0 == rwflag);
    int len = snprintf(buf, bufsz, "%s", keyfile->pwd);
    if (bufsz <= len) return 0;
    return len;
}

static int tls_keyfile_ctor(struct tls_keyfile *keyfile, char const *path, char const *pwd, struct ip_addr const *net, struct ip_addr const *mask, bool is_mask, struct proto *proto)
{
    SLOG(LOG_DEBUG, "Construct keyfile@%p '%s' for '%s', proto %s", keyfile, path, ip_addr_2_str(net), proto->name);

    // Initialize our only SSL_CTX, with a single private key, that we will use for everything
    keyfile->ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    if (! keyfile->ssl_ctx) {
        SLOG(LOG_ERR, "SSL error while initializing keyfile %s: %s", path, openssl_errors_2_str());
        goto err0;
    }
    // Load private key file
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
    keyfile->is_mask = is_mask;
    keyfile->proto = proto;
    HASH_INIT(&keyfile->sessions, 67, "TLS Sessions");
    TAILQ_INIT(&keyfile->sessions_lru);
    mutex_ctor(&keyfile->lock, "TLS keyfile");

    WITH_LOCK(&tls_keyfiles_lock) {
        LIST_INSERT_HEAD(&tls_keyfiles, keyfile, entry);
    }
    return 0;
err1:
    SSL_CTX_free(keyfile->ssl_ctx);
err0:
    return -1;
}

static struct tls_keyfile *tls_keyfile_new(char const *path, char const *pwd, struct ip_addr const *net, struct ip_addr const *mask, bool is_mask, struct proto *proto)
{
    struct tls_keyfile *keyfile = objalloc(sizeof(*keyfile), "keyfiles");
    if (! keyfile) return NULL;
    if (0 != tls_keyfile_ctor(keyfile, path, pwd, net, mask, is_mask, proto)) {
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

    struct tls_session *session;
    while (NULL != (session = TAILQ_LAST(&keyfile->sessions_lru, tls_sessions_lru))) {
        tls_session_del(session, keyfile);
    }
    assert(0 == HASH_SIZE(&keyfile->sessions));
    HASH_DEINIT(&keyfile->sessions);

    mutex_dtor(&keyfile->lock);
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

static bool ip_match_keyfile(struct ip_addr const *ip, struct tls_keyfile const *keyfile)
{
    if (keyfile->is_mask) {
        return ip_addr_match_mask(ip, &keyfile->net, &keyfile->mask);
    } else {
        return ip_addr_match_range(ip, &keyfile->net, &keyfile->mask);
    }
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
static SCM g_tls_add_key(SCM file_, SCM net_, SCM mask_, SCM is_mask_, SCM proto_, SCM pwd_)
{
    (void)pwd_; // TODO

    char const *file = scm_to_tempstr(file_);
    struct ip_addr net, mask;
    if (0 != scm_netmask_2_ip_addr2(&net, &mask, net_, mask_)) return SCM_BOOL_F;
    bool is_mask = scm_to_bool(is_mask_);
    struct proto *proto = proto_of_scm_name(proto_);
    if (! proto) return SCM_BOOL_F;

    struct tls_keyfile *keyfile = tls_keyfile_new(file, NULL, &net, &mask, is_mask, proto);
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
    SLOG(LOG_DEBUG, "Does cipher %u uses RSA?", cipher);
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
        case TLS_RSA_WITH_CAMELLIA_128_CBC_SHA:
        case TLS_RSA_WITH_CAMELLIA_256_CBC_SHA:
        case TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256:
            SLOG(LOG_DEBUG, " ...yep!");
            return true;
        default:
            SLOG(LOG_DEBUG, " ...noooo... :'(");
            return false;
    }
}

static bool rsa_cipher_is_ephemeral(enum tls_cipher_suite cipher)
{
    SLOG(LOG_DEBUG, "Is cipher %u ephemeral?", cipher);

    switch (cipher) {
        case TLS_RSA_EXPORT_WITH_RC4_40_MD5:
        case TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5:
        case TLS_RSA_EXPORT_WITH_DES40_CBC_SHA:
            SLOG(LOG_DEBUG, " ...yes... :'(");
            return true;
        default:
            SLOG(LOG_DEBUG, " ...and no!");
            return false;
    }
}

static struct tls_cipher_info {
    // FIXME: enums
#   define KEX_RSA     0x10
#   define KEX_DH      0x11
#   define ENC_DES     0x30
#   define ENC_3DES    0x31
#   define ENC_RC4     0x32
#   define ENC_RC2     0x33
#   define ENC_IDEA    0x34
#   define ENC_AES128  0x35
#   define ENC_AES256  0x36
#   define ENC_NULL    0x37
#   define ENC_CML128  0x39
#   define ENC_CML256  0x40
#   define DIG_MD5     0x50
#   define DIG_SHA     0x51
    bool defined;
    EVP_CIPHER const *ciph;
    int kex;    // key exchenge
    int enc;
    int block;
    int bits;
    int eff_bits;
    int dig;
    int export;
} tls_cipher_infos[] = {
    [TLS_RSA_WITH_NULL_MD5] =                   { true, NULL, KEX_RSA,ENC_NULL,   0,  0,  0,DIG_MD5,0 },
    [TLS_RSA_WITH_NULL_SHA] =                   { true, NULL, KEX_RSA,ENC_NULL,   0,  0,  0,DIG_SHA,0 },
    [TLS_RSA_EXPORT_WITH_RC4_40_MD5] =          { true, NULL, KEX_RSA,ENC_RC4,    1,128, 40,DIG_MD5,1 },
    [TLS_RSA_WITH_RC4_128_MD5] =                { true, NULL, KEX_RSA,ENC_RC4,    1,128,128,DIG_MD5,0 },
    [TLS_RSA_WITH_RC4_128_SHA] =                { true, NULL, KEX_RSA,ENC_RC4,    1,128,128,DIG_SHA,0 },
    [TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5] =      { true, NULL, KEX_RSA,ENC_RC2,    8,128, 40,DIG_MD5,1 },
    [TLS_RSA_WITH_IDEA_CBC_SHA] =               { true, NULL, KEX_RSA,ENC_IDEA,   8,128,128,DIG_SHA,0 },
    [TLS_RSA_EXPORT_WITH_DES40_CBC_SHA] =       { true, NULL, KEX_RSA,ENC_DES,    8, 64, 40,DIG_SHA,1 },
    [TLS_RSA_WITH_DES_CBC_SHA] =                { true, NULL, KEX_RSA,ENC_DES,    8, 64, 64,DIG_SHA,0 },
    [TLS_RSA_WITH_3DES_EDE_CBC_SHA] =           { true, NULL, KEX_RSA,ENC_3DES,   8,192,192,DIG_SHA,0 },
    [TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA] =    { true, NULL, KEX_DH, ENC_DES,    8, 64, 40,DIG_SHA,1 },
    [TLS_DH_DSS_WITH_DES_CBC_SHA] =             { true, NULL, KEX_DH, ENC_DES,    8, 64, 64,DIG_SHA,0 },
    [TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA] =        { true, NULL, KEX_DH, ENC_3DES,   8,192,192,DIG_SHA,0 },
    [TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA] =    { true, NULL, KEX_DH, ENC_DES,    8, 64, 40,DIG_SHA,1 },
    [TLS_DH_RSA_WITH_DES_CBC_SHA] =             { true, NULL, KEX_DH, ENC_DES,    8, 64, 64,DIG_SHA,0 },
    [TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA] =        { true, NULL, KEX_DH, ENC_3DES,   8,192,192,DIG_SHA,0 },
    [TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA] =   { true, NULL, KEX_DH, ENC_DES,    8, 64, 40,DIG_SHA,1 },
    [TLS_DHE_DSS_WITH_DES_CBC_SHA] =            { true, NULL, KEX_DH, ENC_DES,    8, 64, 64,DIG_SHA,0 },
    [TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA] =       { true, NULL, KEX_DH, ENC_3DES,   8,192,192,DIG_SHA,0 },
    [TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA] =   { true, NULL, KEX_DH, ENC_DES,    8, 64, 40,DIG_SHA,1 },
    [TLS_DHE_RSA_WITH_DES_CBC_SHA] =            { true, NULL, KEX_DH, ENC_DES,    8, 64, 64,DIG_SHA,0 },
    [TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA] =       { true, NULL, KEX_DH, ENC_3DES,   8,192,192,DIG_SHA,0 },
    [TLS_DH_anon_EXPORT_WITH_RC4_40_MD5] =      { true, NULL, KEX_DH, ENC_RC4,    1,128, 40,DIG_MD5,1 },
    [TLS_DH_anon_WITH_RC4_128_MD5] =            { true, NULL, KEX_DH, ENC_RC4,    1,128,128,DIG_MD5,0 },
    [TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA] =   { true, NULL, KEX_DH, ENC_DES,    8, 64, 40,DIG_SHA,1 },
    [TLS_DH_anon_WITH_DES_CBC_SHA] =            { true, NULL, KEX_DH, ENC_DES,    8, 64, 64,DIG_SHA,0 },
    [TLS_DH_anon_WITH_3DES_EDE_CBC_SHA] =       { true, NULL, KEX_DH, ENC_3DES,   8,192,192,DIG_SHA,0 },
    //
    [TLS_RSA_WITH_AES_128_CBC_SHA] =            { true, NULL, KEX_RSA,ENC_AES128,16,128,128,DIG_SHA,0 },
    [TLS_DH_DSS_WITH_AES_128_CBC_SHA] =         { true, NULL, KEX_DH, ENC_AES128,16,128,128,DIG_SHA,0 },
    [TLS_DH_RSA_WITH_AES_128_CBC_SHA] =         { true, NULL, KEX_DH, ENC_AES128,16,128,128,DIG_SHA,0 },
    [TLS_DHE_DSS_WITH_AES_128_CBC_SHA] =        { true, NULL, KEX_DH, ENC_AES128,16,128,128,DIG_SHA,0 },
    [TLS_DHE_RSA_WITH_AES_128_CBC_SHA] =        { true, NULL, KEX_DH, ENC_AES128,16,128,128,DIG_SHA,0 },
    [TLS_DH_anon_WITH_AES_128_CBC_SHA] =        { true, NULL, KEX_DH, ENC_AES128,16,128,128,DIG_SHA,0 },
    [TLS_RSA_WITH_AES_256_CBC_SHA] =            { true, NULL, KEX_RSA,ENC_AES256,16,256,256,DIG_SHA,0 },
    [TLS_DH_DSS_WITH_AES_256_CBC_SHA] =         { true, NULL, KEX_DH, ENC_AES256,16,256,256,DIG_SHA,0 },
    [TLS_DH_RSA_WITH_AES_256_CBC_SHA] =         { true, NULL, KEX_DH, ENC_AES256,16,256,256,DIG_SHA,0 },
    [TLS_DHE_DSS_WITH_AES_256_CBC_SHA] =        { true, NULL, KEX_DH, ENC_AES256,16,256,256,DIG_SHA,0 },
    [TLS_DHE_RSA_WITH_AES_256_CBC_SHA] =        { true, NULL, KEX_DH, ENC_AES256,16,256,256,DIG_SHA,0 },
    [TLS_DH_anon_WITH_AES_256_CBC_SHA] =        { true, NULL, KEX_DH, ENC_AES256,16,256,256,DIG_SHA,0 },
    //
    [TLS_RSA_WITH_CAMELLIA_128_CBC_SHA] =       { true, NULL, KEX_RSA,ENC_CML128,16,128,128,DIG_SHA,0 },
    [TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA] =    { true, NULL, KEX_DH, ENC_CML128,16,128,128,DIG_SHA,0 },
    [TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA] =    { true, NULL, KEX_DH, ENC_CML128,16,128,128,DIG_SHA,0 },
    [TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA] =   { true, NULL, KEX_DH, ENC_CML128,16,128,128,DIG_SHA,0 },
    [TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA] =   { true, NULL, KEX_DH, ENC_CML128,16,128,128,DIG_SHA,0 },
    [TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA] =   { true, NULL, KEX_DH, ENC_CML128,16,128,128,DIG_SHA,0 },
    //
    [0x60] =                                    { true, NULL, KEX_RSA,ENC_RC4,    1,128, 56,DIG_MD5,1 },
    [0x61] =                                    { true, NULL, KEX_RSA,ENC_RC2,    1,128, 56,DIG_MD5,1 },
    [TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA] =     { true, NULL, KEX_RSA,ENC_DES,    8, 64, 64,DIG_SHA,1 },
    [TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA] = { true, NULL, KEX_DH, ENC_DES,    8, 64, 64,DIG_SHA,1 },
    [TLS_RSA_EXPORT1024_WITH_RC4_56_SHA] =      { true, NULL, KEX_RSA,ENC_RC4,    1,128, 56,DIG_SHA,1 },
    [TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA] =  { true, NULL, KEX_DH, ENC_RC4,    1,128, 56,DIG_SHA,1 },
    [TLS_DHE_DSS_WITH_RC4_128_SHA] =            { true, NULL, KEX_DH, ENC_RC4,    1,128,128,DIG_SHA,0 },
    //
    [TLS_RSA_WITH_CAMELLIA_256_CBC_SHA] =       { true, NULL, KEX_RSA,ENC_CML256,16,256,256,DIG_SHA,0 },
    [TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA] =    { true, NULL, KEX_DH, ENC_CML256,16,256,256,DIG_SHA,0 },
    [TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA] =    { true, NULL, KEX_DH, ENC_CML256,16,256,256,DIG_SHA,0 },
    [TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA] =   { true, NULL, KEX_DH, ENC_CML256,16,256,256,DIG_SHA,0 },
    [TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA] =   { true, NULL, KEX_DH, ENC_CML256,16,256,256,DIG_SHA,0 },
    [TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA] =   { true, NULL, KEX_DH, ENC_CML256,16,256,256,DIG_SHA,0 },
    //
    [TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256] =    { true, NULL, KEX_RSA,ENC_CML128,16,128,128,DIG_SHA,0 },
    [TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256] = { true, NULL, KEX_DH ,ENC_CML128,16,128,128,DIG_SHA,0 },
    [TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256] = { true, NULL, KEX_DH ,ENC_CML128,16,128,128,DIG_SHA,0 },
    [TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256] ={ true, NULL, KEX_DH ,ENC_CML128,16,128,128,DIG_SHA,0 },
    [TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256] ={ true, NULL, KEX_DH ,ENC_CML128,16,128,128,DIG_SHA,0 },
    [TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256] ={ true, NULL, KEX_DH ,ENC_CML128,16,128,128,DIG_SHA,0 },
    [TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256] =    { true, NULL, KEX_DH ,ENC_CML256,16,256,256,DIG_SHA,0 },
    [TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256] = { true, NULL, KEX_DH ,ENC_CML256,16,256,256,DIG_SHA,0 },
    [TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256] = { true, NULL, KEX_DH ,ENC_CML256,16,256,256,DIG_SHA,0 },
    [TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256] ={ true, NULL, KEX_DH ,ENC_CML256,16,256,256,DIG_SHA,0 },
    [TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256] ={ true, NULL, KEX_DH ,ENC_CML256,16,256,256,DIG_SHA,0 },
    [TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256] ={ true, NULL, KEX_DH ,ENC_CML256,16,256,256,DIG_SHA,0 },
};

static size_t tls_digest_len(unsigned dig)
{
    switch (dig) {
        case DIG_MD5: return 16;
        case DIG_SHA: return 20;
    }
    assert(!"Unknown digest type");
}

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
        case ENC_CML128: return "CAMELLIA128";
        case ENC_CML256: return "CAMELLIA256";
    }
    assert(!"Invalid encoder");
}

struct tls_parser {
    struct parser parser;
    unsigned c2s_way;       // The way when traffic is going from client to server (UNSET for unset)
    struct streambuf sbuf;
    /*
     * Cryptographic material (handle with care!)
     */

    // We also keep the master secret so that we can copy it into the session at a latter point
    uint8_t master_secret[SECRET_LEN];
    struct tls_keyfile *keyfile;    // if not NULL, the one that was used to decrypt above master_secret (FIXME: a more formal ref would be nice (or forbid deletion of keyfiles)
    unsigned current[2];   // Tells which spec is in order for this direction, for the client and the server. Never UNSET.
    struct tls_cipher_spec {
        enum tls_cipher_suite cipher;
        enum tls_compress_algo compress;
        struct tls_version version;
        uint8_t key_block[136];     // max required size
        bool decoder_ready;         // if true then decoders are inited
        struct tls_decoder {  // used for the establishment of next crypto keys
#           define RANDOM_LEN 32
            uint8_t random[RANDOM_LEN];
            uint32_t session_id_hash;  // The hash of the session id
            uint32_t session_ticket_hash;   // The hash of the session ticket
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
    tls_parser->keyfile = NULL;
    for (unsigned c = 0; c <=1 ; c++) {
        tls_parser->current[c] = 0;
        tls_parser->spec[c].decoder_ready = false;
        for (unsigned d = 0; d <= 1; d++) {
            // Clear bit 31 of session_id/ticket_hash
            tls_parser->spec[c].decoder[d].session_id_hash = tls_parser->spec[c].decoder[d].session_ticket_hash = 0;
        }
    }
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
    for (unsigned current = 0; current < 2; current ++) {
        for (unsigned way = 0; way < 2; way++) {
            if (! tls_parser->spec[current].decoder_ready) continue;
            EVP_CIPHER_CTX_cleanup(&tls_parser->spec[current].decoder[way].evp);
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
        CASE(NULL_WITH_NULL_NULL);                  CASE(RSA_WITH_NULL_MD5);
        CASE(RSA_WITH_NULL_SHA);                    CASE(RSA_EXPORT_WITH_RC4_40_MD5);
        CASE(RSA_WITH_RC4_128_MD5);                 CASE(RSA_WITH_RC4_128_SHA);
        CASE(RSA_EXPORT_WITH_RC2_CBC_40_MD5);       CASE(RSA_WITH_IDEA_CBC_SHA);
        CASE(RSA_EXPORT_WITH_DES40_CBC_SHA);        CASE(RSA_WITH_DES_CBC_SHA);
        CASE(RSA_WITH_3DES_EDE_CBC_SHA);            CASE(DH_DSS_EXPORT_WITH_DES40_CBC_SHA);
        CASE(DH_DSS_WITH_DES_CBC_SHA);              CASE(DH_DSS_WITH_3DES_EDE_CBC_SHA);
        CASE(DH_RSA_EXPORT_WITH_DES40_CBC_SHA);     CASE(DH_RSA_WITH_DES_CBC_SHA);
        CASE(DH_RSA_WITH_3DES_EDE_CBC_SHA);         CASE(DHE_DSS_EXPORT_WITH_DES40_CBC_SHA);
        CASE(DHE_DSS_WITH_DES_CBC_SHA);             CASE(DHE_DSS_WITH_3DES_EDE_CBC_SHA);
        CASE(DHE_RSA_EXPORT_WITH_DES40_CBC_SHA);    CASE(DHE_RSA_WITH_DES_CBC_SHA);
        CASE(DHE_RSA_WITH_3DES_EDE_CBC_SHA);        CASE(DH_anon_EXPORT_WITH_RC4_40_MD5);
        CASE(DH_anon_WITH_RC4_128_MD5);             CASE(DH_anon_EXPORT_WITH_DES40_CBC_SHA);
        CASE(DH_anon_WITH_DES_CBC_SHA);             CASE(DH_anon_WITH_3DES_EDE_CBC_SHA);
        CASE(RSA_WITH_AES_128_CBC_SHA);             CASE(DH_DSS_WITH_AES_128_CBC_SHA);
        CASE(DH_RSA_WITH_AES_128_CBC_SHA);          CASE(DHE_DSS_WITH_AES_128_CBC_SHA);
        CASE(DHE_RSA_WITH_AES_128_CBC_SHA);         CASE(DH_anon_WITH_AES_128_CBC_SHA);
        CASE(RSA_WITH_AES_256_CBC_SHA);             CASE(DH_DSS_WITH_AES_256_CBC_SHA);
        CASE(DH_RSA_WITH_AES_256_CBC_SHA);          CASE(DHE_DSS_WITH_AES_256_CBC_SHA);
        CASE(DHE_RSA_WITH_AES_256_CBC_SHA);         CASE(DH_anon_WITH_AES_256_CBC_SHA);
        CASE(RSA_WITH_NULL_SHA256);                 CASE(RSA_WITH_AES_128_CBC_SHA256);
        CASE(RSA_WITH_AES_256_CBC_SHA256);          CASE(DH_DSS_WITH_AES_128_CBC_SHA256);
        CASE(DH_RSA_WITH_AES_128_CBC_SHA256);       CASE(DHE_DSS_WITH_AES_128_CBC_SHA256);
        CASE(RSA_WITH_CAMELLIA_128_CBC_SHA);        CASE(DH_DSS_WITH_CAMELLIA_128_CBC_SHA);
        CASE(DH_RSA_WITH_CAMELLIA_128_CBC_SHA);     CASE(DHE_DSS_WITH_CAMELLIA_128_CBC_SHA);
        CASE(DHE_RSA_WITH_CAMELLIA_128_CBC_SHA);    CASE(DH_anon_WITH_CAMELLIA_128_CBC_SHA);
        CASE(RSA_EXPORT1024_WITH_DES_CBC_SHA);      CASE(DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA);
        CASE(RSA_EXPORT1024_WITH_RC4_56_SHA);       CASE(DHE_DSS_EXPORT1024_WITH_RC4_56_SHA);
        CASE(DHE_DSS_WITH_RC4_128_SHA);
        CASE(DHE_RSA_WITH_AES_128_CBC_SHA256);      CASE(DH_DSS_WITH_AES_256_CBC_SHA256);
        CASE(DH_RSA_WITH_AES_256_CBC_SHA256);       CASE(DHE_DSS_WITH_AES_256_CBC_SHA256);
        CASE(DHE_RSA_WITH_AES_256_CBC_SHA256);      CASE(DH_anon_WITH_AES_128_CBC_SHA256);
        CASE(DH_anon_WITH_AES_256_CBC_SHA256);      CASE(RSA_WITH_CAMELLIA_256_CBC_SHA);
        CASE(DH_DSS_WITH_CAMELLIA_256_CBC_SHA);     CASE(DH_RSA_WITH_CAMELLIA_256_CBC_SHA);
        CASE(DHE_DSS_WITH_CAMELLIA_256_CBC_SHA);    CASE(DHE_RSA_WITH_CAMELLIA_256_CBC_SHA);
        CASE(DH_anon_WITH_CAMELLIA_256_CBC_SHA);    CASE(RSA_WITH_CAMELLIA_128_CBC_SHA256);
        CASE(DH_DSS_WITH_CAMELLIA_128_CBC_SHA256);  CASE(DH_RSA_WITH_CAMELLIA_128_CBC_SHA256);
        CASE(DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256); CASE(DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256);
        CASE(DH_anon_WITH_CAMELLIA_128_CBC_SHA256); CASE(RSA_WITH_CAMELLIA_256_CBC_SHA256);
        CASE(DH_DSS_WITH_CAMELLIA_256_CBC_SHA256);  CASE(DH_RSA_WITH_CAMELLIA_256_CBC_SHA256);
        CASE(DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256); CASE(DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256);
        CASE(DH_anon_WITH_CAMELLIA_256_CBC_SHA256);
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

static int tls_P_hash(SSL unused_ *ssl, uint8_t const *restrict secret, size_t seed_len, uint8_t const *restrict seed, const EVP_MD *md, size_t out_len, uint8_t *restrict out)
{
    HMAC_CTX hm;

#   define SEED_MAX_LEN 128
    assert(seed_len <= SEED_MAX_LEN);
    unsigned char A[MAX(EVP_MAX_MD_SIZE, SEED_MAX_LEN)];
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
#   define MAX_LABEL_LEN 64
    assert(label_len <= MAX_LABEL_LEN);
    uint8_t seed[MAX_LABEL_LEN + RANDOM_LEN + RANDOM_LEN];
    size_t const actual_seed_len = label_len + RANDOM_LEN + RANDOM_LEN;
    memcpy(seed, label, label_len);
    memcpy(seed + label_len, r1, RANDOM_LEN);
    memcpy(seed + label_len + RANDOM_LEN, r2, RANDOM_LEN);

#   define MAX_OUT_LEN 256
    size_t const md5_out_len = MAX(out_len, 16);
    assert(md5_out_len <= MAX_OUT_LEN);
    uint8_t md5_out[MAX_OUT_LEN];
    size_t const sha_out_len = MAX(out_len, 20);
    assert(sha_out_len <= MAX_OUT_LEN);
    uint8_t sha_out[MAX_OUT_LEN];

    if (0 != tls_P_hash(ssl, secret,                actual_seed_len, seed, EVP_get_digestbyname("MD5"),  md5_out_len, md5_out)) return -1;
    if (0 != tls_P_hash(ssl, secret + SECRET_LEN/2, actual_seed_len, seed, EVP_get_digestbyname("SHA1"), sha_out_len, sha_out)) return -1;

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

// decrypt the pre_master_secret using server's private key (or saved session_id).
// Note: we follow ssldump footpath from there!
// Note2: way is clt->srv way
static int decrypt_master_secret_with_keyfile(struct tls_keyfile *keyfile, struct tls_parser *parser, size_t enc_pms_len, uint8_t const *encrypted_pms)
{
    int err = -1;

    SLOG(LOG_DEBUG, "Try to decrypt Master Secret using keyfile %s", keyfile->path);

    SSL *ssl = SSL_new(keyfile->ssl_ctx);
    if (! ssl) {
        SLOG(LOG_ERR, "Cannot create SSL from SSL_CTX: %s", openssl_errors_2_str());
        goto quit0;
    }
    EVP_PKEY *pk = SSL_get_privatekey(ssl);
    if (! pk) {
        SLOG(LOG_ERR, "Cannot get private key from SSL object: %s", openssl_errors_2_str());
        goto quit1;
    }
    if (pk->type != EVP_PKEY_RSA) {
        SLOG(LOG_ERR, "Private key is not a RSA key.");
        // oh, well
    }

    struct tls_cipher_spec *clt_next_spec = &parser->spec[!parser->current[parser->c2s_way]];
    struct tls_decoder *clt_next_decoder = &clt_next_spec->decoder[parser->c2s_way];
    struct tls_decoder *srv_next_decoder = &parser->spec[!parser->current[!parser->c2s_way]].decoder[!parser->c2s_way];

    uint8_t *master_secret = NULL; // decrypt it from encrypted_master_secret or retrieve it from saved session
    if (encrypted_pms) {
        uint8_t pre_master_secret[SECRET_LEN];  //RSA_size(pk->pkey.rsa)];
        int const pms_len = RSA_private_decrypt(enc_pms_len, encrypted_pms, pre_master_secret, pk->pkey.rsa, RSA_PKCS1_PADDING);
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

        if (0 != prf(clt_next_spec->version, ssl,
                     pre_master_secret, "master secret",
                     clt_next_decoder->random,
                     srv_next_decoder->random,
                     sizeof(parser->master_secret),
                     parser->master_secret))
            goto quit1;

        parser->keyfile = keyfile;
        master_secret = parser->master_secret;
    } else {    // !encrypted_pms but we can use session_id
        // We do not bother coming here with no usable session_id
        assert((clt_next_decoder->session_id_hash & KEY_HASH_SET) && (srv_next_decoder->session_id_hash & KEY_HASH_SET));
        // Look for this session_id in keyfile
        struct tls_session *session = NULL;
        WITH_LOCK(&keyfile->lock) {
            if (clt_next_decoder->session_id_hash & KEY_HASH_SET) {
                HASH_LOOKUP(session, &keyfile->sessions, &clt_next_decoder->session_id_hash, id_hash, h_entry_id);
                if (session) SLOG(LOG_DEBUG, "Reusing session id for %"PRIu32" (hash)", session->id_hash);
            }
            if (! session && clt_next_decoder->session_ticket_hash & KEY_HASH_SET) {
                HASH_LOOKUP(session, &keyfile->sessions, &clt_next_decoder->session_ticket_hash, ticket_hash, h_entry_ticket);
                if (session) SLOG(LOG_DEBUG, "Reusing session ticket for %"PRIu32" (hash)", session->ticket_hash);
            }
        }

        if (! session) {
            SLOG(LOG_DEBUG, "No reusable session, give up decryption");
            goto quit1;
        }
        // FIXME: protect this session with a ref of some sort to prevent another thread to delete it
        tls_session_promote(session, keyfile);
        master_secret = session->master_secret;  // TODO: a ref?
    }

    assert(master_secret);

    if (clt_next_spec->cipher >= NB_ELEMS(tls_cipher_infos)) {
unknown_cipher:
        SLOG(LOG_DEBUG, "Don't know the characteristics of cipher %s", tls_cipher_suite_2_str(clt_next_spec->cipher));
        goto quit1;
    }
    struct tls_cipher_info const *cipher_info = tls_cipher_infos + clt_next_spec->cipher;
    if (! cipher_info->defined) goto unknown_cipher;

    unsigned const needed =
        tls_digest_len(cipher_info->dig)*2 +
        cipher_info->bits/4 +
        (cipher_info->block > 1 ? cipher_info->block*2 : 0);
    assert(needed <= sizeof(clt_next_spec->key_block));

    if (0 != prf(clt_next_spec->version, ssl,
                 master_secret, "key expansion",
                 srv_next_decoder->random,
                 clt_next_decoder->random,
                 needed, clt_next_spec->key_block))
        goto quit1;
    SLOG(LOG_DEBUG, "key_block:");
    SLOG_HEX(LOG_DEBUG, clt_next_spec->key_block, needed);

    // Save cryptographic material from the key_block
    // TODO: handle export ciphers?
    uint8_t *ptr = clt_next_spec->key_block;
    clt_next_decoder->mac_key = ptr; ptr += tls_digest_len(cipher_info->dig);
    srv_next_decoder->mac_key = ptr; ptr += tls_digest_len(cipher_info->dig);
    clt_next_decoder->write_key = ptr; ptr += cipher_info->eff_bits/8;
    srv_next_decoder->write_key = ptr; ptr += cipher_info->eff_bits/8;
    if (cipher_info->block > 1) {
        clt_next_decoder->init_vector = ptr; ptr += cipher_info->block;
        srv_next_decoder->init_vector = ptr; ptr += cipher_info->block;
    }

    // prepare a cipher for both directions
    for (unsigned dir = 0; dir < 2; dir ++) {
        if (clt_next_spec->decoder_ready) {
            EVP_CIPHER_CTX_cleanup(&clt_next_spec->decoder[dir].evp);
        }
        EVP_CIPHER_CTX_init(&clt_next_spec->decoder[dir].evp);
        if (1 != EVP_CipherInit(&clt_next_spec->decoder[dir].evp, cipher_info->ciph, clt_next_spec->decoder[dir].write_key, clt_next_spec->decoder[dir].init_vector, 0)) {
            // Error
            SLOG(LOG_INFO, "Cannot initialize cipher suite 0x%x: %s", clt_next_spec->cipher, openssl_errors_2_str());
            goto quit1;
        }
    }
    clt_next_spec->decoder_ready = true;

    // Prepare a subparser (if we haven't one yet)
    if (! parser->subparser && keyfile->proto) {
        SLOG(LOG_DEBUG, "Spawn new TLS subparser for proto %s", keyfile->proto->name);
        parser->subparser = keyfile->proto->ops->parser_new(keyfile->proto);
        if (! parser->subparser) {
            SLOG(LOG_WARNING, "Cannot create TLS subparser for proto %s", keyfile->proto->name);
            goto quit1;
        }
    }

    err = 0;
quit1:
    SSL_free(ssl);
quit0:
    return err;
}

static int decrypt_master_secret(struct tls_parser *parser, unsigned way, struct tls_proto_info const *info, size_t enc_pms_len, uint8_t const *encrypted_pms)
{
    unsigned const srv_idx = way == parser->c2s_way ? 1 : 0;
    SLOG(LOG_DEBUG, "way=%u, parser->c2s_way=%u -> srv_idx=%u", way, parser->c2s_way, srv_idx);

    // find the relevant(s) keyfile(s)
    ASSIGN_INFO_OPT(tcp, &info->info);
    if (! tcp) return -1;
    ASSIGN_INFO_OPT(ip, &tcp->info);
    if (! ip) return -1;
    struct tls_keyfile *keyfile;
    WITH_LOCK(&tls_keyfiles_lock) {
        LIST_FOREACH(keyfile, &tls_keyfiles, entry) {
            if (! ip_match_keyfile(&ip->key.addr[srv_idx], keyfile)) continue;
            if (0 == decrypt_master_secret_with_keyfile(keyfile, parser, enc_pms_len, encrypted_pms)) {
                break;
            }
        }
    }

    if (! keyfile) {
        SLOG(LOG_DEBUG, "No (working) keyfile found for %s:%"PRIu16, ip_addr_2_str(&ip->key.addr[srv_idx]), tcp->key.port[srv_idx]);
        return -1;
    }

    return 0;
}

static enum proto_parse_status look_for_cname(struct cursor *cur, void *info_)
{
    struct tls_proto_info *info = info_;
    enum proto_parse_status status;
    SLOG(LOG_DEBUG, "Enter the RelativeDistinguishedName");
    if (PROTO_OK != (status = ber_enter(cur))) return status;  // enter the RelativeDistinguishedName
    SLOG(LOG_DEBUG, "Enter the AttributeValueAssertion");
    if (PROTO_OK != (status = ber_enter(cur))) return status;  // enter the AttributeValueAssertion
    SLOG(LOG_DEBUG, "Look for commonName");
    // Look for commonName (in DER)
    if (cur->cap_len < 5) return PROTO_TOO_SHORT;
    if (
        cur->head[0] == 0x6 && cur->head[1] == 0x3 && cur->head[2] == 0x55 &&
        cur->head[3] == 0x4 && cur->head[4] == 0x3
    ) {
        SLOG(LOG_DEBUG, "Found commonName!!");
        cursor_drop(cur, 5);
        if (PROTO_OK != (status = ber_decode_string(cur, sizeof(info->u.handshake.server_common_name), info->u.handshake.server_common_name))) return status;
        SLOG(LOG_DEBUG, "CN: %s", info->u.handshake.server_common_name);
        info->set_values |= SERVER_COMMON_NAME_SET;
    } else {
        SLOG(LOG_DEBUG, "Not the commonName...");
        // Not commonName
        if (PROTO_OK != (status = ber_skip(cur))) return status;
        if (PROTO_OK != (status = ber_skip(cur))) return status;
    }

    return PROTO_OK;
}

static enum proto_parse_status tls_parse_certificate(struct tls_proto_info *info, struct cursor *cur)
{
    SLOG(LOG_DEBUG, "Parsing TLS certificate");
    enum proto_parse_status status;
    SLOG(LOG_DEBUG, "Enter the Certificate");
    if (PROTO_OK != (status = ber_enter(cur))) return status; // enter the Certificate
    SLOG(LOG_DEBUG, "Enter the TBSCertificate");
    if (PROTO_OK != (status = ber_enter(cur))) return status; // enter the TBSCertificate
    SLOG(LOG_DEBUG, "Skip optional Version");
    if (PROTO_OK != (status = ber_skip_optional(cur, 0))) return status;  // skip the optional Version (tag 0)
    SLOG(LOG_DEBUG, "Skip the serial number");
    if (PROTO_OK != (status = ber_skip(cur))) return status;  // skip the serial number
    SLOG(LOG_DEBUG, "Skip the signature");
    if (PROTO_OK != (status = ber_skip(cur))) return status;  // skip the signature
    SLOG(LOG_DEBUG, "Skip the issuer");
    if (PROTO_OK != (status = ber_skip(cur))) return status;  // skip the issuer
    SLOG(LOG_DEBUG, "Skip the validity");
    if (PROTO_OK != (status = ber_skip(cur))) return status;  // skip the validity
    SLOG(LOG_DEBUG, "iter over all RelativeDistinguishedName");
    if (PROTO_OK != (status = ber_foreach(cur, look_for_cname, info))) return status; // iter over all RelativeDistinguishedName and look for the common name
    SLOG(LOG_DEBUG, "Successively parsed certificate");
    return PROTO_OK;
}

static enum proto_parse_status copy_session(uint32_t *key_hash, size_t len, struct cursor *cur)
{
    if (cur->cap_len < len) return PROTO_TOO_SHORT;
    if (len > 0) {
        *key_hash = tls_session_key_hash(len, cur->head) | KEY_HASH_SET;
        SLOG(LOG_DEBUG, "Saving session ticket which hash is %"PRIu32, *key_hash);
        cursor_drop(cur, len);
    }
    return PROTO_OK;
}

// Rather than copying it we only save it's digest
static enum proto_parse_status copy_session_id(uint32_t *key_hash, struct cursor *cur)
{
    if (cur->cap_len < 1) return PROTO_TOO_SHORT;
    uint8_t const id_len = cursor_read_u8(cur);
    return copy_session(key_hash, id_len, cur);
}

static enum proto_parse_status len1_skip(struct cursor *cur)
{
    if (cur->cap_len < 1) return PROTO_TOO_SHORT;
    uint8_t len = cursor_read_u8(cur);
    if (cur->cap_len < len) return PROTO_TOO_SHORT;
    cursor_drop(cur, len);
    return PROTO_OK;
}

static enum proto_parse_status len2_skip(struct cursor *cur)
{
    if (cur->cap_len < 2) return PROTO_TOO_SHORT;
    uint16_t len = cursor_read_u16n(cur);
    if (cur->cap_len < len) return PROTO_TOO_SHORT;
    cursor_drop(cur, len);
    return PROTO_OK;
}

static enum proto_parse_status tls_parse_extensions(struct tls_decoder *next_decoder, struct cursor *cur)
{
    SLOG(LOG_DEBUG, "Parsing TLS extensions");

    while (cur->cap_len > 0) {
        if (cur->cap_len < 4) {
            return PROTO_TOO_SHORT;
        }
        uint16_t tag = cursor_read_u16n(cur);
        uint16_t len = cursor_read_u16n(cur);
        if (cur->cap_len < len) return PROTO_TOO_SHORT;
        enum proto_parse_status err;
        switch (tag) {
            case 0x0023:    // SessionTicket
                if ((err = copy_session(&next_decoder->session_ticket_hash, len, cur)) != PROTO_OK) return err;
                break;
            default:
                cursor_drop(cur, len);
                break;
        }
    }

    return PROTO_OK;
}

enum tls_handshake_type {
    tls_hello_request = 0, tls_client_hello, tls_server_hello,
    tls_server_new_session_ticket = 4,
    tls_certificate = 11, tls_server_key_exchange, tls_certificate_request,
    tls_server_hello_done, tls_certificate_verify, tls_client_key_exchange,
    tls_finished = 20,
};

static char const *tls_handshake_type_2_str(enum tls_handshake_type type)
{
    switch (type) {
        case tls_hello_request:       return "Hello Request";
        case tls_client_hello:        return "Client Hello";
        case tls_server_hello:        return "Server Hello";
        case tls_server_new_session_ticket:
                                      return "Server New Session Ticket";
        case tls_certificate:         return "Certificate";
        case tls_server_key_exchange: return "Server Key Exchange";
        case tls_certificate_request: return "Certificate Request";
        case tls_server_hello_done:   return "Server Hello Done";
        case tls_certificate_verify:  return "Certificate Verify";
        case tls_client_key_exchange: return "Client Key Exchange";
        case tls_finished:            return "Finished";
        default:                      return tempstr_printf("unknown (%u)", type);
    }
}

static enum proto_parse_status tls_parse_handshake(struct tls_parser *parser, unsigned way, struct tls_proto_info *info, struct cursor *cur, size_t wire_len)
{
    SLOG(LOG_DEBUG, "%zu bytes on wire, %zu captured, way=%u", wire_len, cur->cap_len, way);

    if (cur->cap_len < 4) {
        if (wire_len >= 4) return PROTO_TOO_SHORT;
        return PROTO_PARSE_ERR;
    }
    enum tls_handshake_type type = cursor_read_u8(cur);
    SLOG(LOG_DEBUG, "Parsing handshake record of type %s", tls_handshake_type_2_str(type));
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
            // Save the session_id
            if ((err = copy_session_id(&next_decoder->session_id_hash, &tcur)) != PROTO_OK) return err;
            /*
             * go for a session ticket extension
             */
            // skip cipher suites
            if ((err = len2_skip(&tcur)) != PROTO_OK) {
quit_parse:
                if (err == PROTO_TOO_SHORT) break;
                return err;
            }
            // skip compression method
            if ((err = len1_skip(&tcur)) != PROTO_OK) goto quit_parse;
            // parse extensions
            if ((err = tls_parse_extensions(next_decoder, &tcur)) != PROTO_OK) goto quit_parse;
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
            // Read session_id
            if ((err = copy_session_id(&next_decoder->session_id_hash, &tcur)) != PROTO_OK) return err;
            // Save cipher infos
            if (tcur.cap_len < 3) return PROTO_TOO_SHORT;
            next_spec->cipher = cursor_read_u16n(&tcur);
            next_spec->compress = cursor_read_u8(&tcur);
            // Should we resume an old session?
            struct tls_decoder *clt_next_decoder = &parser->spec[!parser->current[!way]].decoder[!way];
            if (
                (next_decoder->session_id_hash & KEY_HASH_SET) &&
                next_decoder->session_id_hash == clt_next_decoder->session_id_hash
                // Note: we may have a session ticket (sent in client hello) _in_addition_.
            ) {
                if (0 != decrypt_master_secret(parser, way, info, 0, NULL)) {
                    // too bad.
                }
            }
            // the user might want to know
            info->set_values |= CIPHER_SUITE_SET;
            info->u.handshake.cipher_suite = next_spec->cipher;
            info->u.handshake.compress_algorithm = next_spec->compress;
            break;
        case tls_server_new_session_ticket:
            // fix c2s_way
            parser->c2s_way = !way;
            // This message is composed of: lifetime hint (4 bytes, big endian), length (2 bytes), then ticket
            if (length <= 6) return PROTO_PARSE_ERR;
            cursor_drop(&tcur, 4);  // we accept whatever type
            unsigned ticket_len = cursor_read_u16n(&tcur);
            if ((err = copy_session(&next_decoder->session_ticket_hash, ticket_len, &tcur)) != PROTO_OK) return err;
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
            (void)tls_parse_certificate(info, &cert);    // best effort only, as our BER decoder is not perfect
            break;
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
        case tls_finished:
            // At the end of the handshake, optionally saves the master_secret into a session
            if (parser->keyfile) {
                struct tls_cipher_spec *srv_spec = parser->spec + parser->current[!parser->c2s_way];
                struct tls_decoder *srv_decoder = srv_spec->decoder + !parser->c2s_way;
                if ((srv_decoder->session_id_hash | srv_decoder->session_ticket_hash) & KEY_HASH_SET) {
                    (void)tls_session_new(parser->keyfile, srv_decoder->session_id_hash, srv_decoder->session_ticket_hash, parser->master_secret);
                }
            }
            break;
        // TODO: other cases to fix c2s way as well
        default:
            SLOG(LOG_DEBUG, "Skipping handshake message of type %u", type);
            break;
    }

    // Go to next message in this record
    if (wire_len == length) {
        SLOG(LOG_DEBUG, "Done with this record");
        return PROTO_OK;    // we are done
    }
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
    // its value is supposed to be 1
    if (cur->cap_len >= 1 && cur->head[0] != 1) goto invalid;

    // TODO: if we still lack the decryption key but we have session_ticket_hash from client then try to resume this session

    // put next crypto material into production
    parser->current[way] ^= 1;
    SLOG(LOG_DEBUG, "Put in production new decoder for way %u (c2s is %u), (%sset)", way, parser->c2s_way, parser->spec[parser->current[way]].decoder_ready ? "":"un");

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
            SLOG(LOG_INFO, "Cannot decrypt record: %s", openssl_errors_2_str());
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
    if (tls_digest_len(cipher_info->dig) > *out_sz) {
        SLOG(LOG_DEBUG, "Cannot decrypt: no space for a MAC?");
        return -1;
    }
    *out_sz -= tls_digest_len(cipher_info->dig);

    SLOG(LOG_INFO, "Successfully decrypted %zu bytes!", *out_sz);
    SLOG_HEX(LOG_INFO, out, *out_sz);
    SLOG(LOG_DEBUG, "(%.*s)", (int)*out_sz, out);

    return 0;
}

static enum proto_parse_status tls_parse_record(struct tls_parser *parser, unsigned way, struct tls_proto_info *info, size_t cap_len, size_t wire_len, uint8_t const *payload, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct tls_cipher_spec *spec = &parser->spec[parser->current[way]];
    bool const is_crypted = spec->cipher != TLS_NULL_WITH_NULL_NULL;
    struct cursor cur;

    SLOG(LOG_DEBUG, "Parse new record, %zu bytes captured (%zu on the wire)%s", cap_len, wire_len, is_crypted ? ", crypted":"");

    if (is_crypted) {
        unsigned char *decrypted = alloca(wire_len);    // Cannot use buffer here since we want reentry
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
        tls_parser->c2s_way = way;
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
static struct port_muxer tcp_port_muxer_ftps;

void tls_init(void)
{
    log_category_proto_tls_init();
    hash_init();

    LIST_INIT(&tls_keyfiles);
    mutex_ctor(&tls_keyfiles_lock, "TLS keyfiles");

    X509V3_add_standard_extensions();   // ssldump does this

    ext_param_max_sessions_per_key_init();

    // Initialize all ciphers
    for (unsigned c = 0; c < NB_ELEMS(tls_cipher_infos); c++) {
        struct tls_cipher_info *info = tls_cipher_infos+c;
        if (! info->defined) continue;
        if (info->enc == ENC_NULL) {
            info->ciph = EVP_enc_null();
        } else {
            info->ciph = EVP_get_cipherbyname(cipher_name_of_enc(info->enc));
            /* Note regarding IDEA: RFC5469 suggest IDEA should be retired from TLS
             * on the ground that it's not well tested. It's not implemented by
             * openssl (and probably many others). So don't bark if it's missing. */
            if (! info->ciph && info->enc != ENC_IDEA) {
                SLOG(LOG_ERR, "Cannot initialize cipher for suite 0x%x, enc %u, name %s: %s", c, info->enc, cipher_name_of_enc(info->enc), openssl_errors_2_str());
            }
        }
    }

    static struct proto_ops const ops = {
        .parse       = tls_parse,
        .parser_new  = tls_parser_new,
        .parser_del  = tls_parser_del,
        .info_2_str  = tls_info_2_str,
        .info_addr   = tls_info_addr
    };
    proto_ctor(&proto_tls_, &ops, "TLS", PROTO_CODE_TLS);
    port_muxer_ctor(&tcp_port_muxer_https, &tcp_port_muxers, 443, 443, proto_tls);
    port_muxer_ctor(&tcp_port_muxer_skinny, &tcp_port_muxers, 2443, 2443, proto_tls);
    port_muxer_ctor(&tcp_port_muxer_ftps, &tcp_port_muxers, 989, 990, proto_tls);

    // Extension functions to add keyfiles
    ext_function_ctor(&sg_tls_keys,
        "tls-keys", 0, 0, 0, g_tls_keys,
        "(tls-keys): returns a list of all known private keys.\n");

    ext_function_ctor(&sg_tls_add_key,
        "tls-add-key", 5, 1, 0, g_tls_add_key,
        "(tls-add-key \"/var/keys/secret.pem\" \"192.168.1.42\" \"255.255.255.255\" #t \"http\"): use this key to decrypt HTTP traffic to this IP.\n"
        "Optionally, you can pass a password (used to decrypt the file) as another argument.\n"
        "See also (? 'tls-del-key)\n");

    ext_function_ctor(&sg_tls_del_key,
        "tls-del-key", 1, 0, 0, g_tls_del_key,
        "(tls-del-key \"/var/keys/secret.pem\"): forget about this key.\n"
        "See also (? 'tls-add-key)\n");
}

void tls_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    port_muxer_dtor(&tcp_port_muxer_ftps, &tcp_port_muxers);
    port_muxer_dtor(&tcp_port_muxer_skinny, &tcp_port_muxers);
    port_muxer_dtor(&tcp_port_muxer_https, &tcp_port_muxers);

    proto_dtor(&proto_tls_);

    struct tls_keyfile *keyfile;
    while (NULL != (keyfile = LIST_FIRST(&tls_keyfiles))) {
        tls_keyfile_del(keyfile);
    }
    mutex_dtor(&tls_keyfiles_lock);
#   endif

    ext_param_max_sessions_per_key_fini();

    hash_fini();
    log_category_proto_tls_fini();
}
