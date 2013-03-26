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
#include "junkie/tools/objalloc.h"
#include "junkie/tools/miscmacs.h"
#include "junkie/proto/streambuf.h"
#include "junkie/proto/port_muxer.h"
#include "junkie/proto/cursor.h"
#include "junkie/proto/tcp.h"
#include "junkie/proto/tls.h"

#undef LOG_CAT
#define LOG_CAT proto_tls_log_category

LOG_CATEGORY_DEF(proto_tls);

enum tls_cipher_suite {
    TLS_NULL_WITH_NULL_NULL,
    TLS_RSA_WITH_NULL_MD5,
    TLS_RSA_WITH_NULL_SHA,
    TLS_RSA_EXPORT_WITH_RC4_40_MD5,
    TLS_RSA_WITH_RC4_128_MD5,
    TLS_RSA_WITH_RC4_128_SHA,
    TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
    TLS_RSA_WITH_IDEA_CBC_SHA,
    TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
    TLS_RSA_WITH_DES_CBC_SHA,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,
    TLS_DH_DSS_WITH_DES_CBC_SHA,
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
    TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
    TLS_DH_RSA_WITH_DES_CBC_SHA,
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
    TLS_DHE_DSS_WITH_DES_CBC_SHA,
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
    TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
    TLS_DHE_RSA_WITH_DES_CBC_SHA,
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
    TLS_DH_anon_WITH_RC4_128_MD5,
    TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA,
    TLS_DH_anon_WITH_DES_CBC_SHA,
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,
};

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
            return true;
        default:
            return false;
    }
}

enum tls_compress_algo {
    TLS_COMPRESS_NULL,
};

struct tls_parser {
    struct parser parser;
    unsigned c2s_way;       // The way when traffic is going from client to server (UNSET for unset)
    struct streambuf sbuf;
    // Cryptographic material (handle with care!)
#   define FROM_CLIENT 0
#   define FROM_SERVER 1
    struct tls_next_ciph {  // used for the establishment of next crypto keys
#       define RANDOM_LENGTH 32
        uint8_t random[2][RANDOM_LENGTH];
        enum tls_cipher_suite cipher;
        enum tls_compress_algo compress;
        unsigned rsa_pre_master_len;
        uint8_t rsa_pre_master[2][256];
    } next_ciph;
};


static parse_fun tls_sbuf_parse;
static int tls_parser_ctor(struct tls_parser *tls_parser, struct proto *proto)
{
    SLOG(LOG_DEBUG, "Constructing tls_parser@%p", tls_parser);
    assert(proto == proto_tls);
    if (0 != parser_ctor(&tls_parser->parser, proto)) return -1;
    tls_parser->c2s_way = UNSET;
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
    parser_dtor(&tls_parser->parser);
    streambuf_dtor(&tls_parser->sbuf);
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

static char const *tls_info_2_str(struct proto_info const *info_)
{
    struct tls_proto_info const *info = DOWNCAST(info_, info, tls_proto_info);
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "%s, version=%"PRIu8".%"PRIu8", content-type=%s",
        proto_info_2_str(&info->info),
        info->version.maj, info->version.min,
        tls_content_type_2_str(info->content_type));
    return str;
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

static enum proto_parse_status skip_version(struct cursor *cur)
{
    uint8_t maj = cursor_read_u8(cur);
    uint8_t min = cursor_read_u8(cur);
    return maj <= 3 && min <= 10 ? PROTO_OK : PROTO_PARSE_ERR;
}

static enum proto_parse_status skip_session(struct cursor *cur)
{
    if (cur->cap_len < 1) return PROTO_TOO_SHORT;
    uint8_t len = cursor_read_u8(cur);
    if (cur->cap_len < len) return PROTO_TOO_SHORT;
    cursor_drop(cur, len);
    return PROTO_OK;
}

static enum proto_parse_status tls_parse_handshake(struct tls_parser *parser, struct tls_proto_info *info, struct cursor *cur, size_t unused_ wire_len)
{
    enum tls_handshake_type {
        tls_hello_request = 0, tls_client_hello, tls_server_hello,
        tls_certificate = 11, tls_server_key_exchange, tls_certificate_request,
        tls_server_hello_done, tls_certificate_verify, tls_client_key_exchange,
        tls_finished = 20,
    };

    if (cur->cap_len < 3) return PROTO_TOO_SHORT;
    enum tls_handshake_type type = cursor_read_u8(cur);
    unsigned unused_ length = cursor_read_u16n(cur);
    enum proto_parse_status err;

    switch (type) {
#       define VERSION_LENGTH 2
        case tls_client_hello:
            // Save random
            if (cur->cap_len < VERSION_LENGTH+RANDOM_LENGTH) return PROTO_TOO_SHORT;
            if ((err = skip_version(cur)) != PROTO_OK) return err;
            ASSERT_COMPILE(sizeof(parser->next_ciph.random[FROM_CLIENT]) == RANDOM_LENGTH);
            cursor_copy(&parser->next_ciph.random[FROM_CLIENT], cur, RANDOM_LENGTH);
            break;    // done with this record
        case tls_server_hello:
            // Save random, selected cipher suite and compression algorithm
            if (cur->cap_len < VERSION_LENGTH+RANDOM_LENGTH) return PROTO_TOO_SHORT;
            if ((err = skip_version(cur)) != PROTO_OK) return err;
            ASSERT_COMPILE(sizeof(parser->next_ciph.random[FROM_SERVER]) == RANDOM_LENGTH);
            cursor_copy(&parser->next_ciph.random[FROM_SERVER], cur, RANDOM_LENGTH);
            if ((err = skip_session(cur)) != PROTO_OK) return err;
            if (cur->cap_len < 3) return PROTO_TOO_SHORT;
            parser->next_ciph.cipher = cursor_read_u16n(cur);
            parser->next_ciph.compress = cursor_read_u8(cur);
            // the user might want to know
            info->set_values &= CIPHER_SUITE_SET;
            info->u.handshake.cipher_suite = parser->next_ciph.cipher;
            info->u.handshake.compress_algorithm = parser->next_ciph.compress;
            break;
        case tls_client_key_exchange:
            if (cipher_uses_rsa(info->u.handshake.cipher_suite)) {
                if (cur->cap_len < 2) return PROTO_TOO_SHORT;
                unsigned len = cursor_read_u16(cur);
                if (cur->cap_len < len) return PROTO_TOO_SHORT;
                // save cryptographic material
                if (len > sizeof(parser->next_ciph.rsa_pre_master[FROM_CLIENT])) {
                    SLOG(LOG_WARNING, "Cannot save RSA pre master key from client: len was %u bytes", len);
                } else {
                    parser->next_ciph.rsa_pre_master_len = len; // FIXME: set to 0 at start
                    cursor_copy(&parser->next_ciph.rsa_pre_master[FROM_CLIENT], cur, len);
                }
            }
            break;
        default:
            SLOG(LOG_DEBUG, "Skipping handshake message of type %u", type);
            break;
    }

    return PROTO_OK;
}

static enum proto_parse_status tls_parse_change_cipher_spec(struct tls_parser *parser, struct tls_proto_info *info, struct cursor *cur, size_t wire_len)
{
    (void)parser; (void)info; (void)cur; (void)wire_len;
    return PROTO_OK;
}

static enum proto_parse_status tls_parse_alert(struct tls_parser *parser, struct tls_proto_info *info, struct cursor *cur, size_t wire_len)
{
    (void)parser; (void)info; (void)cur; (void)wire_len;
    return PROTO_OK;
}

static enum proto_parse_status tls_parse_application_data(struct tls_parser *parser, struct tls_proto_info *info, struct cursor *cur, size_t wire_len)
{
    (void)parser; (void)info; (void)cur; (void)wire_len;
    return PROTO_OK;
}

static enum proto_parse_status tls_parse_record(struct tls_parser *parser, struct tls_proto_info *info, struct cursor *cur, size_t wire_len)
{
    switch (info->content_type) {
        case tls_handshake:
            return tls_parse_handshake(parser, info, cur, wire_len);
        case tls_change_cipher_spec:
            return tls_parse_change_cipher_spec(parser, info, cur, wire_len);
        case tls_alert:
            return tls_parse_alert(parser, info, cur, wire_len);
        case tls_application_data:
            return tls_parse_application_data(parser, info, cur, wire_len);
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

    struct cursor cur;
    cursor_ctor(&cur, payload, cap_len);
    enum tls_content_type content_type = cursor_read_u8(&cur);
    unsigned proto_version_maj = cursor_read_u8(&cur);
    unsigned proto_version_min = cursor_read_u8(&cur);
    unsigned length = cursor_read_u16n(&cur);

    // Sanity checks
    if (proto_version_maj > 3 || content_type < tls_change_cipher_spec || content_type > tls_application_data) {
        SLOG(LOG_DEBUG, "Don't look like TLS");
        return PROTO_PARSE_ERR;
    }

    if (wire_len < TLS_RECORD_HEAD + length) goto restart_record;

    // Now build the proto_info
    struct tls_proto_info info;
    proto_info_ctor(&info.info, parser, parent, wire_len, 0);
    info.version.maj = proto_version_maj;
    info.version.min = proto_version_min;
    info.content_type = content_type;
    info.set_values = 0;

    // Parse the rest of the record according to the content_type
    streambuf_set_restart(&tls_parser->sbuf, way, payload + TLS_RECORD_HEAD + length, false);

    enum proto_parse_status status = tls_parse_record(tls_parser, &info, &cur, wire_len - TLS_RECORD_HEAD /* what we have read so far */);

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
static struct port_muxer tcp_port_muxer;

void tls_init(void)
{
    log_category_proto_tls_init();

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
    port_muxer_ctor(&tcp_port_muxer, &tcp_port_muxers, 443, 443, proto_tls);
}

void tls_fini(void)
{
    port_muxer_dtor(&tcp_port_muxer, &tcp_port_muxers);

    proto_dtor(&proto_tls_);
    log_category_proto_tls_fini();
}
