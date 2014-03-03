// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2010, SecurActive.
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
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <limits.h>
#include <iconv.h>
#include "junkie/cpp.h"
#include "junkie/tools/log.h"
#include "junkie/tools/tempstr.h"
#include "junkie/tools/objalloc.h"
#include "junkie/proto/proto.h"
#include "junkie/proto/tcp.h"
#include "junkie/proto/tds.h"
#include "junkie/proto/sql.h"
#include "junkie/proto/streambuf.h"
#include "junkie/proto/cursor.h"

// Use same logger as TDS 'transport'
#undef LOG_CAT
#define LOG_CAT proto_tds_log_category

enum env_change_token {
    ENV_DATABASE = 0x01,
    ENV_LANGUAGE,
    ENV_CHARACTER_SET,
    ENV_PACKET_SIZE,
    ENV_UNICODE_LOCAL_ID,
    ENV_UNICODE_COMPARISON_FLAG,
    ENV_COLLATION,
    ENV_BEGIN_TRANSACTION,
    ENV_COMMIT_TRANSACTION,
    ENV_ROLLBACK_TRANSACTION,
    ENV_ENLIST_TRANSACTION,
    ENV_DEFECT_TRANSACTION,
    ENV_REAL_TIME_LOG,
    ENV_PROMOTE_TRANSACTION,
    ENV_TRANSACTION_MANAGER,
    ENV_TRANSACTION_ENDED,
    ENV_RESET_CONNECTION,
    ENV_SEND_BACK_INSTANCE,
    ENV_SEND_ROUTING_INFO,
};

// token definitions
enum tds_msg_token {
    // Data Buffer Stream Tokens
    ALTMETADATA_TOKEN            = 0x88,
    ALTROW_TOKEN                 = 0xD3,
    COLMETADATA_TOKEN            = 0x81,
    COLINFO_TOKEN                = 0xA5,
    DONE_TOKEN                   = 0xFD,
    DONEPROC_TOKEN               = 0xFE,
    DONEINPROC_TOKEN             = 0xFF,
    ENV_CHANGE_TOKEN             = 0xE3,
    ERROR_TOKEN                  = 0xAA,
    FEATUREEXTACK_TOKEN          = 0xAE,
    INFO_TOKEN                   = 0xAB,
    LOGINACK_TOKEN               = 0xAD,
    NBCROW_TOKEN                 = 0xD2,
    OFFSET_TOKEN                 = 0x78,
    ORDER_TOKEN                  = 0xA9,
    RETURNSTATUS_TOKEN           = 0x79,
    RETURNVALUE_TOKEN            = 0xAC,
    ROW_TOKEN                    = 0xD1,
    SESSIONSTATE_TOKEN           = 0xE4,
    SSPI_TOKEN                   = 0xED,
    TABNAME_TOKEN                = 0xA4,
};

/* TODO: prelogin messages can also be TLS handshake. */
enum tds_msg_pl_option_token {
    TDS_VERSION = 0,
    TDS_ENCRYPTION,
    TDS_INSTOPT,
    TDS_THREADID,
    TDS_MARS,
    TDS_TRACEID,
    TDS_TERMINATOR = 0xff
};

enum tds_msg_encryption_option {
    TDS_ENCRYPT_OFF,
    TDS_ENCRYPT_ON,
    TDS_ENCRYPT_NOT_SUP,
    TDS_ENCRYPT_REQ,
};

// Token for determining the type of data
enum type_info_token {
    NULLTYPE            = 0x1F,
    INT1TYPE            = 0x30,
    BITTYPE             = 0x32,
    INT2TYPE            = 0x34,
    INT4TYPE            = 0x38,
    DATETIM4TYPE        = 0x3A,
    FLT4TYPE            = 0x3B,
    MONEYTYPE           = 0x3C,
    DATETIMETYPE        = 0x3D,
    FLT8TYPE            = 0x3E,
    MONEY4TYPE          = 0x7A,
    INT8TYPE            = 0x7F,
    GUIDTYPE            = 0x24,
    INTNTYPE            = 0x26,
    DECIMALTYPE         = 0x37,
    NUMERICTYPE         = 0x3F,
    BITNTYPE            = 0x68,
    DECIMALNTYPE        = 0x6A,
    NUMERICNTYPE        = 0x6C,
    FLTNTYPE            = 0x6D,
    MONEYNTYPE          = 0x6E,
    DATETIMNTYPE        = 0x6F,
    DATENTYPE           = 0x28,
    TIMENTYPE           = 0x29,
    DATETIME2NTYPE      = 0x2A,
    DATETIMEOFFSETNTYPE = 0x2B,
    CHARTYPE            = 0x2F,
    VARCHARTYPE         = 0x27,
    BINARYTYPE          = 0x2D,
    VARBINARYTYPE       = 0x25,
    BIGVARBINTYPE       = 0xA5,
    BIGVARCHRTYPE       = 0xA7,
    BIGBINARYTYPE       = 0xAD,
    BIGCHARTYPE         = 0xAF,
    NVARCHARTYPE        = 0xE7,
    NCHARTYPE           = 0xEF,
    XMLTYPE             = 0xF1,
    UDTTYPE             = 0xF0,
    TEXTTYPE            = 0x23,
    IMAGETYPE           = 0x22,
    NTEXTTYPE           = 0x63,
    SSVARIANTTYPE       = 0x62,
};

enum type_info_type {
    ZERO_LENGTH_TOKEN,
    FIXED_LENGTH_TOKEN,
    VARIABLE_LENGTH_TOKEN,
    VARIABLE_COUNT_TOKEN,
    PARTIALY_LENGTH_PREFIXED,
};

static char const *tds_msg_token_2_str(enum tds_msg_token tok)
{
    switch (tok) {
        case ALTMETADATA_TOKEN: return "ALTMETADATA";
        case ALTROW_TOKEN: return "ALTROW";
        case COLMETADATA_TOKEN: return "COLMETADATA";
        case COLINFO_TOKEN: return "COLINFO";
        case DONE_TOKEN: return "DONE";
        case DONEPROC_TOKEN: return "DONEPROC";
        case DONEINPROC_TOKEN: return "DONEINPROC";
        case ENV_CHANGE_TOKEN: return "ENV_CHANGE";
        case ERROR_TOKEN: return "ERROR";
        case FEATUREEXTACK_TOKEN: return "FEATUREEXTACK";
        case INFO_TOKEN: return "INFO";
        case LOGINACK_TOKEN: return "LOGINACK";
        case NBCROW_TOKEN: return "NBCROW";
        case OFFSET_TOKEN: return "OFFSET";
        case ORDER_TOKEN: return "ORDER";
        case RETURNSTATUS_TOKEN: return "RETURNSTATUS";
        case RETURNVALUE_TOKEN: return "RETURNVALUE";
        case ROW_TOKEN: return "ROW";
        case SESSIONSTATE_TOKEN: return "SESSIONSTATE";
        case SSPI_TOKEN: return "SSPI";
        case TABNAME_TOKEN: return "TABNAME";
    }
    return tempstr_printf("unknown token (%u)", tok);
}

static char const *tds_msg_prelogin_token_2_str(enum tds_msg_pl_option_token tok)
{
    switch (tok) {
        case TDS_VERSION: return "TDS_VERSION";
        case TDS_ENCRYPTION: return "TDS_ENCRYPTION";
        case TDS_INSTOPT: return "TDS_INSTOPT";
        case TDS_THREADID: return "TDS_THREADID";
        case TDS_MARS: return "TDS_MARS";
        case TDS_TRACEID: return "TDS_TRACEID";
        case TDS_TERMINATOR: return "TDS_TERMINATOR ";
    }
    return tempstr_printf("unknown token (%u)", tok);
}

static char const *type_info_token_2_str(enum type_info_token tok)
{
    switch (tok) {
        case NULLTYPE: return "NULLTYPE";
        case INT1TYPE: return "INT1TYPE";
        case BITTYPE: return "BITTYPE";
        case INT2TYPE: return "INT2TYPE";
        case INT4TYPE: return "INT4TYPE";
        case DATETIM4TYPE: return "DATETIM4TYPE";
        case FLT4TYPE: return "FLT4TYPE";
        case MONEYTYPE: return "MONEYTYPE";
        case DATETIMETYPE: return "DATETIMETYPE";
        case FLT8TYPE: return "FLT8TYPE";
        case MONEY4TYPE: return "MONEY4TYPE";
        case INT8TYPE: return "INT8TYPE";
        case GUIDTYPE: return "GUIDTYPE";
        case INTNTYPE: return "INTNTYPE";
        case DECIMALTYPE: return "DECIMALTYPE";
        case NUMERICTYPE: return "NUMERICTYPE";
        case BITNTYPE: return "BITNTYPE";
        case DECIMALNTYPE: return "DECIMALNTYPE";
        case NUMERICNTYPE: return "NUMERICNTYPE";
        case FLTNTYPE: return "FLTNTYPE";
        case MONEYNTYPE: return "MONEYNTYPE";
        case DATETIMNTYPE: return "DATETIMNTYPE";
        case DATENTYPE: return "DATENTYPE";
        case TIMENTYPE: return "TIMENTYPE";
        case DATETIME2NTYPE: return "DATETIME2NTYPE";
        case DATETIMEOFFSETNTYPE: return "DATETIMEOFFSETNTYPE";
        case CHARTYPE: return "CHARTYPE";
        case VARCHARTYPE: return "VARCHARTYPE";
        case BINARYTYPE: return "BINARYTYPE";
        case VARBINARYTYPE: return "VARBINARYTYPE";
        case BIGVARBINTYPE: return "BIGVARBINTYPE";
        case BIGVARCHRTYPE: return "BIGVARCHRTYPE";
        case BIGBINARYTYPE: return "BIGBINARYTYPE";
        case BIGCHARTYPE: return "BIGCHARTYPE";
        case NVARCHARTYPE: return "NVARCHARTYPE";
        case NCHARTYPE: return "NCHARTYPE";
        case XMLTYPE: return "XMLTYPE";
        case UDTTYPE: return "UDTTYPE";
        case TEXTTYPE: return "TEXTTYPE";
        case IMAGETYPE: return "IMAGETYPE";
        case NTEXTTYPE: return "NTEXTTYPE";
        case SSVARIANTTYPE: return "SSVARIANTTYPE";
    }
    return tempstr_printf("unknown token (%u)", tok);
}

static char const *env_change_token_2_str(enum env_change_token tok)
{
    switch (tok) {
        case ENV_DATABASE: return "ENV_DATABASE";
        case ENV_LANGUAGE: return "ENV_LANGUAGE";
        case ENV_CHARACTER_SET: return "ENV_CHARACTER_SET";
        case ENV_PACKET_SIZE: return "ENV_PACKET_SIZE";
        case ENV_UNICODE_LOCAL_ID: return "ENV_UNICODE_LOCAL_ID";
        case ENV_UNICODE_COMPARISON_FLAG: return "ENV_UNICODE_COMPARISON_FLAG";
        case ENV_COLLATION: return "ENV_COLLATION";
        case ENV_BEGIN_TRANSACTION: return "ENV_BEGIN_TRANSACTION";
        case ENV_COMMIT_TRANSACTION: return "ENV_COMMIT_TRANSACTION";
        case ENV_ROLLBACK_TRANSACTION: return "ENV_ROLLBACK_TRANSACTION";
        case ENV_ENLIST_TRANSACTION: return "ENV_ENLIST_TRANSACTION";
        case ENV_DEFECT_TRANSACTION: return "ENV_DEFECT_TRANSACTION";
        case ENV_REAL_TIME_LOG: return "ENV_REAL_TIME_LOG";
        case ENV_PROMOTE_TRANSACTION: return "ENV_PROMOTE_TRANSACTION";
        case ENV_TRANSACTION_MANAGER: return "ENV_TRANSACTION_MANAGER";
        case ENV_TRANSACTION_ENDED: return "ENV_TRANSACTION_ENDED";
        case ENV_RESET_CONNECTION: return "ENV_RESET_CONNECTION";
        case ENV_SEND_BACK_INSTANCE: return "ENV_SEND_BACK_INSTANCE";
        case ENV_SEND_ROUTING_INFO: return "ENV_SEND_ROUTING_INFO";
    }
    return tempstr_printf("unknown token (%u)", tok);
}

static char const *type_info_type_2_str(enum type_info_type tok)
{
    switch (tok) {
        case ZERO_LENGTH_TOKEN: return "ZERO_LENGTH_TOKEN";
        case FIXED_LENGTH_TOKEN: return "FIXED_LENGTH_TOKEN";
        case VARIABLE_LENGTH_TOKEN: return "VARIABLE_LENGTH_TOKEN";
        case VARIABLE_COUNT_TOKEN: return "VARIABLE_COUNT_TOKEN";
        case PARTIALY_LENGTH_PREFIXED: return "PARTIALY_LENGTH_PREFIXED";
    }
    return tempstr_printf("unknown token (%u)", tok);
}

struct type_info {
    enum type_info_token token;
    enum type_info_type type;
    // For variable length, it is the size of size
    // For fix length, it is the size of the value
    size_t size;
};

static char const *type_info_2_str(struct type_info const *type_info)
{
    return tempstr_printf("Token=%s, Type=%s, size=%zu",
             type_info_token_2_str(type_info->token), type_info_type_2_str(type_info->type),
             type_info->size);
}

# define MAX_TYPE_INFO 100
struct tds_msg_parser {
    struct parser parser;
    unsigned c2s_way;       // The way when traffic is going from client to server (or UNSET)
    enum tds_packet_type last_pkt_type;
    // A flag giving precious information on how to decode some values (see MSTDS, 2.2.6.3)
#   define F_BYTEORDER 0x01
#   define F_CHAR      0x02
#   define F_FLOAT     0x0C // 2 bits
#   define F_DUMPLOAD  0x10
#   define F_USE_DB    0x20
#   define F_DATABASE  0x40
#   define F_SET_LANG  0x80
    uint8_t option_flag_1;
    bool pre_7_2;           // true if we run an old version of the protocol
    struct streambuf sbuf;  // yep, one more level of buffering
    unsigned column_count;
    struct type_info type_info[MAX_TYPE_INFO]; // Type info extracted from COLMETADATA
    iconv_t iconv_cd;               // Conversion descriptor for reading unicode
    bool had_gap;
};

static parse_fun tds_msg_sbuf_parse;

static int tds_msg_parser_ctor(struct tds_msg_parser *tds_msg_parser, struct proto *proto)
{
    SLOG(LOG_DEBUG, "Constructing tds_msg_parser@%p", tds_msg_parser);
    assert(proto == proto_tds_msg);
    if (0 != parser_ctor(&tds_msg_parser->parser, proto)) return -1;
    tds_msg_parser->c2s_way = UNSET;
    tds_msg_parser->last_pkt_type = 0;
    tds_msg_parser->option_flag_1 = 0;  // ASCII + LittleEndian by default
    tds_msg_parser->pre_7_2 = false;    // assume recent protocol version
    tds_msg_parser->had_gap = false;
    if (0 != streambuf_ctor(&tds_msg_parser->sbuf, tds_msg_sbuf_parse, 30000)) return -1;

    tds_msg_parser->iconv_cd = iconv_open("UTF8//IGNORE", "UCS2");
    if (tds_msg_parser->iconv_cd == ((iconv_t) - 1)) {
        SLOG(LOG_NOTICE, "Could not open iconv: %s", strerror(errno));
        streambuf_dtor(&tds_msg_parser->sbuf);
        return -1;
    }

    return 0;
}

static struct parser *tds_msg_parser_new(struct proto *proto)
{
    struct tds_msg_parser *tds_msg_parser = objalloc_nice(sizeof(*tds_msg_parser), "TDS(msg) parsers");
    if (! tds_msg_parser) return NULL;

    if (-1 == tds_msg_parser_ctor(tds_msg_parser, proto)) {
        objfree(tds_msg_parser);
        return NULL;
    }

    return &tds_msg_parser->parser;
}

static void tds_msg_parser_dtor(struct tds_msg_parser *tds_msg_parser)
{
    SLOG(LOG_DEBUG, "Destructing tds_msg_parser@%p", tds_msg_parser);
    parser_dtor(&tds_msg_parser->parser);
    streambuf_dtor(&tds_msg_parser->sbuf);
    iconv_close(tds_msg_parser->iconv_cd);
}

static void tds_msg_parser_del(struct parser *parser)
{
    struct tds_msg_parser *tds_msg_parser = DOWNCAST(parser, parser, tds_msg_parser);
    tds_msg_parser_dtor(tds_msg_parser);
    objfree(tds_msg_parser);
}

/*
 * Some parse helper
 */

// dst_size is the size of dst buffer
// dst_pos is the position in dst
// str_len is number of bytes to read from cursor
static void append_from_unicode(struct tds_msg_parser const *tds_msg_parser, char *dst, size_t dst_size,
        size_t *dst_pos, struct cursor *cursor, size_t str_len)
{
    assert(cursor->cap_len >= str_len);
    if (!dst || (dst_size == *dst_pos)) {
        SLOG(LOG_DEBUG, "No buffer available for unicode append");
        cursor_drop(cursor, str_len);
        return;
    }
    assert(dst_size > 0);

    SLOG(LOG_DEBUG, "Appending a unicode str of length %zu @%zu (max %zu))", str_len, *dst_pos, dst_size);
    char *output = dst + *dst_pos;
    size_t output_len = dst_size - *dst_pos;
    char *start_output = output;
    unsigned char const *input = (unsigned const char *)cursor->head;
    size_t input_len = str_len;

    size_t ret = iconv(tds_msg_parser->iconv_cd, (char **)&input, &input_len, &output, &output_len);
    if (ret == (size_t) -1) {
        SLOG(LOG_NOTICE, "Iconv error: %s", strerror(errno));
    }
    size_t written_bytes = output - start_output;
    *dst_pos = MIN(*dst_pos + written_bytes, dst_size - 1);
    dst[*dst_pos] = '\0';
    SLOG(LOG_DEBUG, "Converted %zu bytes: '%s'", written_bytes, start_output);
    cursor_drop(cursor, str_len);
}

static void append_string(char *dst, size_t dst_size, size_t *dst_pos, char const *str)
{
    if (!dst) return;
    if (*dst_pos >= dst_size) return;
    *dst_pos += snprintf(dst + *dst_pos, dst_size - *dst_pos, "%s", str);
}

static char hexdigit(int n)
{
    return "0123456789abcdef"[n];
}

// same as above, but display as hex bytes instead of chars
static void append_hexstring(char *dst, size_t dst_size, size_t *dst_pos, struct cursor *cursor, size_t bytes_len)
{
    if (!dst) {
        cursor_drop(cursor, bytes_len);
        return;
    }
    SLOG(LOG_DEBUG, "Appending a hexstring of length %zu @%zu)", bytes_len, *dst_pos);

    while (bytes_len-- > 0) {
        uint8_t c = cursor_read_u8(cursor);
        if (*dst_pos < dst_size-2) {
            dst[(*dst_pos)++] = hexdigit(c>>4);
            dst[(*dst_pos)++] = hexdigit(c&15);
        }
    }
    dst[MIN(*dst_pos, dst_size - 1)] = '\0';
}

// Varchar with a size on 1 byte followed by unicode string
static enum proto_parse_status append_b_varchar(struct tds_msg_parser const *tds_msg_parser, char *dst, size_t dst_size, size_t *dst_pos,
        struct cursor *cursor, char const *default_str)
{
    CHECK(1);
    size_t str_len = cursor_read_u8(cursor);
    CHECK(str_len*2);
    if (!dst) {
        cursor_drop(cursor, str_len*2);
    } else if (0 == str_len) {
        if (default_str) append_string(dst, dst_size, dst_pos, default_str);
    } else {
        SLOG(LOG_DEBUG, "Appending a B_VARCHAR of length %zu into @%zu in buffer of size %zu", str_len, *dst_pos, dst_size);
        append_from_unicode(tds_msg_parser, dst, dst_size, dst_pos, cursor, str_len * 2);
    }
    return PROTO_OK;
}

static enum proto_parse_status skip_b_varchar(struct cursor *cursor)
{
    return append_b_varchar(NULL, NULL, 0, NULL, cursor, NULL);
}

// Varchar with a size on 2 byte followed by unicode string
static enum proto_parse_status append_us_varchar(struct tds_msg_parser const *tds_msg_parser, char *dst, size_t dst_size,
        size_t *dst_pos, struct cursor *cursor)
{
    CHECK(2);
    size_t str_len = cursor_read_u16le(cursor);
    CHECK(str_len*2);
    if (!dst) {
        cursor_drop(cursor, str_len * 2);
        return PROTO_OK;
    }
    SLOG(LOG_DEBUG, "Appending a US_VARCHAR of length %zu @%zu in buffer of size %zu", str_len, *dst_pos, dst_size);
    append_from_unicode(tds_msg_parser, dst, dst_size, dst_pos, cursor, str_len * 2);
    return PROTO_OK;
}

static enum proto_parse_status skip_us_varchar(struct cursor *cursor)
{
    return append_us_varchar(NULL, NULL, 0, NULL, cursor);
}

/*
 * Parse
 */

static unsigned type_info_variant_bytes(enum type_info_token tok)
{
    switch (tok) {
        case TIMENTYPE:
        case DATETIME2NTYPE:
        case DATETIMEOFFSETNTYPE:
            // Scale byte
            return 1;
        case NUMERICNTYPE:
        case DECIMALNTYPE:
            // 1 byte precision, 1 byte scale
            return 2;
        case BIGVARCHRTYPE:
        case BIGCHARTYPE:
        case NVARCHARTYPE:
        case NCHARTYPE:
            return 5;
        case BIGVARBINTYPE:
        case BIGBINARYTYPE:
            // Max bytes already parsed as token to size?
            return 0;
        default:
            return 0;
    }
}

static bool type_is_text(enum type_info_token tok)
{
    switch (tok) {
        case BIGCHARTYPE:
        case BIGVARCHRTYPE:
        case TEXTTYPE:
        case NTEXTTYPE:
        case NCHARTYPE:
        case NVARCHARTYPE:
        case XMLTYPE:
            return true;
        default:
            return false;
    }
}

// Give the size of the value for fixed length types
// Otherwise, give the size of size for variable length types
static size_t type_info_token_to_size(enum type_info_token tok)
{
    switch (tok) {
        // FIXEDLENTYPE
        case NULLTYPE:
            return 0;
        case INT1TYPE:
        case BITTYPE:
            return 1;
        case INT2TYPE:
            return 2;
        case INT4TYPE:
        case DATETIM4TYPE:
        case FLT4TYPE:
        case MONEY4TYPE:
            return 4;
        case MONEYTYPE:
        case DATETIMETYPE:
        case FLT8TYPE:
        case INT8TYPE:
            return 8;
        // BYTELEN_TYPE
        case GUIDTYPE:
        case INTNTYPE:
        case DECIMALTYPE:
        case NUMERICTYPE:
        case BITNTYPE:
        case DECIMALNTYPE:
        case NUMERICNTYPE:
        case FLTNTYPE:
        case MONEYNTYPE:
        case DATETIMNTYPE:
        case DATENTYPE:
        case TIMENTYPE:
        case DATETIME2NTYPE:
        case DATETIMEOFFSETNTYPE:
        case CHARTYPE:
        case VARCHARTYPE:
        case BINARYTYPE:
        case VARBINARYTYPE:
            return 1;
        // USHORTLEN_TYPE
        case BIGVARBINTYPE:
        case BIGVARCHRTYPE:
        case BIGBINARYTYPE:
        case BIGCHARTYPE:
        case NVARCHARTYPE:
        case NCHARTYPE:
            return 2;
        // LONGLEN_TYPE
        case IMAGETYPE:
        case NTEXTTYPE:
        case SSVARIANTTYPE:
        case TEXTTYPE:
        case XMLTYPE:
            return 4;
            break;
        default:
            SLOG(LOG_DEBUG, "don't known how to skip TYPE_INFO for token %u", tok);
            return 0;
    }
}

static bool is_type_info_token(enum type_info_token token)
{
    switch (token) {
        case NULLTYPE:
        case INT1TYPE:
        case BITTYPE:
        case INT2TYPE:
        case INT4TYPE:
        case DATETIM4TYPE:
        case FLT4TYPE:
        case MONEYTYPE:
        case DATETIMETYPE:
        case FLT8TYPE:
        case MONEY4TYPE:
        case INT8TYPE:
        case GUIDTYPE:
        case INTNTYPE:
        case DECIMALTYPE:
        case NUMERICTYPE:
        case BITNTYPE:
        case DECIMALNTYPE:
        case NUMERICNTYPE:
        case FLTNTYPE:
        case MONEYNTYPE:
        case DATETIMNTYPE:
        case DATENTYPE:
        case TIMENTYPE:
        case DATETIME2NTYPE:
        case DATETIMEOFFSETNTYPE:
        case CHARTYPE:
        case VARCHARTYPE:
        case BINARYTYPE:
        case VARBINARYTYPE:
        case BIGVARBINTYPE:
        case BIGVARCHRTYPE:
        case BIGBINARYTYPE:
        case BIGCHARTYPE:
        case NVARCHARTYPE:
        case NCHARTYPE:
        case TEXTTYPE:
        case IMAGETYPE:
        case NTEXTTYPE:
        case SSVARIANTTYPE:
        case UDTTYPE:
        case XMLTYPE:
            return true;
        default:
            return false;
    }
}

static enum proto_parse_status parse_type_info(struct tds_msg_parser const *tds_msg_parser,
        struct cursor *cursor, struct type_info *out_type_info)
{
    SLOG(LOG_DEBUG, "Parsing type info");
    struct type_info type_info;
    type_info.size = 0;
    CHECK(1);
    type_info.token = cursor_read_u8(cursor);

    switch (type_info.token) {
        case NULLTYPE:
            {
                type_info.type = ZERO_LENGTH_TOKEN;
                type_info.size = 0;
                break;
            }
        case INT1TYPE:
        case BITTYPE:
        case INT2TYPE:
        case INT4TYPE:
        case DATETIM4TYPE:
        case FLT4TYPE:
        case MONEYTYPE:
        case DATETIMETYPE:
        case FLT8TYPE:
        case MONEY4TYPE:
        case INT8TYPE:
            {
                type_info.type = FIXED_LENGTH_TOKEN;
                type_info.size = 1 << ((type_info.token >> 2) & 3);
                break;
            }
        case GUIDTYPE:
        case INTNTYPE:
        case DECIMALTYPE:
        case NUMERICTYPE:
        case BITNTYPE:
        case DECIMALNTYPE:
        case NUMERICNTYPE:
        case FLTNTYPE:
        case MONEYNTYPE:
        case DATETIMNTYPE:
        case DATENTYPE:
        case TIMENTYPE:
        case DATETIME2NTYPE:
        case DATETIMEOFFSETNTYPE:
        case CHARTYPE:
        case VARCHARTYPE:
        case BINARYTYPE:
        case VARBINARYTYPE:
        case BIGVARBINTYPE:
        case BIGVARCHRTYPE:
        case BIGBINARYTYPE:
        case BIGCHARTYPE:
        case NVARCHARTYPE:
        case NCHARTYPE:
        case TEXTTYPE:
        case IMAGETYPE:
        case NTEXTTYPE:
        case SSVARIANTTYPE:
            {
                type_info.type = VARIABLE_LENGTH_TOKEN;
                type_info.size = type_info_token_to_size(type_info.token);
                CHECK(type_info.size);
                uint_least64_t length;
                cursor_read_fix_int_le(cursor, &length, type_info.size);
                unsigned variant_bytes = type_info_variant_bytes(type_info.token);
                if (variant_bytes) {
                    SLOG(LOG_DEBUG, "Drop %u variant bytes", variant_bytes);
                    CHECK(variant_bytes);
                    cursor_drop(cursor, variant_bytes);
                }
                if (!tds_msg_parser->pre_7_2 && ((type_info.token == BIGVARCHRTYPE || type_info.token == BIGVARBINTYPE ||
                                type_info.token == NVARCHARTYPE) && length > 8000)) {
                    type_info.type = PARTIALY_LENGTH_PREFIXED;
                }
                break;
            }
        case UDTTYPE:
            {
                type_info.type = PARTIALY_LENGTH_PREFIXED;
                break;
            }
        case XMLTYPE:
            {
                type_info.type = PARTIALY_LENGTH_PREFIXED;
                uint8_t schema_present = cursor_read_u8(cursor);
                if (schema_present) {
                    skip_b_varchar(cursor);  // dbname
                    skip_b_varchar(cursor);  // owning_schema
                    skip_us_varchar(cursor); // xml_schema_collection
                }
                break;
            }
        default:
            SLOG(LOG_DEBUG, "Unknown token %d", type_info.token);
            return PROTO_PARSE_ERR;
    }
    if (out_type_info) *out_type_info = type_info;
    return PROTO_OK;
}

static enum proto_parse_status parse_type_info_value(struct tds_msg_parser const *tds_msg_parser,
        char *dst, size_t dst_size, size_t *dst_pos, struct cursor *cursor, struct type_info *type_info)
{
    enum proto_parse_status status;
    switch (type_info->type) {
        case ZERO_LENGTH_TOKEN:
            {
                append_string(dst, dst_size, dst_pos, "NULL");
                break;
            }
        case FIXED_LENGTH_TOKEN:
            {
                uint_least64_t res;
                CHECK(type_info->size);
                cursor_read_fix_int_le(cursor, &res, type_info->size);
                append_string(dst, dst_size, dst_pos, tempstr_printf("%"PRIu64, res));
                break;
            }
        case VARIABLE_LENGTH_TOKEN:
            {
                // Read actual size
                size_t length;
                CHECK(type_info->size);
                status = cursor_read_fix_int_le(cursor, &length, type_info->size);
                if (status != PROTO_OK) return status;

                if (0xFFFFULL == length) length = 0;   // NULL
                else if (0xFFFFFFFFULL == length) length = 0;   // NULL

                SLOG(LOG_DEBUG, "Actual value length %zu (%zu remaining)", length, cursor->cap_len);
                CHECK(length);
                // TODO: specific printer for more complex types
                if (0 == length) {
                    append_string(dst, dst_size, dst_pos, "NULL");
                } else if (type_is_text(type_info->token)) {  // display all kind of texts + Binary + varBinary as text
                    if (type_info->token == NVARCHARTYPE) {
                        append_from_unicode(tds_msg_parser, dst, dst_size, dst_pos, cursor, length);
                    } else {
                        char *str;
                        status = cursor_read_fix_string(cursor, &str, length);
                        if (PROTO_OK != status) return status;
                        append_string(dst, dst_size, dst_pos, str);
                    }
                } else {    // rest as number
                    uint_least64_t value;
                    if (PROTO_OK == cursor_read_fix_int_le(cursor, &value, length)) {
                        append_string(dst, dst_size, dst_pos, tempstr_printf("%"PRIuLEAST64, value));
                    } else {
                        append_hexstring(dst, dst_size, dst_pos, cursor, length);
                    }
                }
                break;
            }
        case VARIABLE_COUNT_TOKEN:
            CHECK(2);
            uint_least16_t nb_fields = cursor_read_u16n(cursor);
            if (nb_fields == 0xffff) {  // COLMETADATA uses this (TODO: check ALTMETADATA)
                nb_fields = 0;  // Cf table at end of 2.2.7.4
            }
            // TODO
            return PROTO_PARSE_ERR;
        case PARTIALY_LENGTH_PREFIXED:
            {
                /* Fear the dreadful addition of TDS 7.2: Partially Length-Prefixed Data type
                 * So this length was only the 2 low bytes of a 8 bytes length (ULONGLONGLEN), or
                 * of a NULL value.  */
#               define PLP_NULL         0xFFFFFFFFFFFFFFFFULL // ...of ones
#               define PLP_UNKNOWN_LEN  0xFFFFFFFFFFFFFFFEULL
#               define PLP_TERMINATOR   0x00000000
                CHECK(8);
                uint_least64_t tot_len = cursor_read_u64le(cursor);
                size_t length;
                if (tot_len == PLP_UNKNOWN_LEN) {
                    SLOG(LOG_DEBUG, "Parsing Partially Length-Prefixed (PLP) Data of unknown length");
                } else if (tot_len < PLP_UNKNOWN_LEN) {
                    SLOG(LOG_DEBUG, "Parsing Partially Length-Prefixed (PLP) Data of total length %"PRIu64, tot_len);
                }

                if (PLP_NULL == tot_len) {   // much ado about nothing. We merely rely on normal code path for NULL.
                    SLOG(LOG_DEBUG, "Parsing Partially Length-Prefixed (PLP) Data Null");
                    length = 0; // NULL
                } else {
                    /* We now have many chunks, which total length is supposed to equal this
                     * 8 bytes lengths, and which must (at least in some cases, the specs
                     * are unclear about other cases) end with a terminator (aka zero length
                     * chunk).
                     * So, are we going to trust the terminator or the total length?
                     * The go for the total length, but stop if we encounter a null length
                     * chunk. Notice that if we managed to buffer the whole message in our
                     * streambuf then the actual total length is probably quite small anyway. */
                    // Parse all chunks
                    while (1) {
                        CHECK(4);
                        length = cursor_read_u32le(cursor);
                        if (tot_len == 0 && length == PLP_TERMINATOR) {
                            break;
                        }
                        SLOG(LOG_DEBUG, "Chunk is %zu bytes long", length);
                        if (0 == length) {
                            SLOG(LOG_DEBUG, "Hit a terminator while still waiting for %zu bytes of total length, stopping there",
                                    tot_len);
                            break;
                        }
                        if (tot_len != PLP_UNKNOWN_LEN && length > tot_len) {
                            SLOG(LOG_DEBUG, "chunk is bigger than total length");
                            return PROTO_PARSE_ERR;
                        }
                        CHECK(length);
                        if (type_is_text(type_info->token)) {
                            append_from_unicode(tds_msg_parser, dst, dst_size, dst_pos, cursor, length);
                        } else {
                            append_hexstring(dst, dst_size, dst_pos, cursor, length);
                        }
                        tot_len -= length;
                    }
                    break;
                }
            }
    }
    return PROTO_OK;
}

static enum proto_parse_status skip_type_info_value(struct cursor *cursor, struct type_info *type_info)
{
    return  parse_type_info_value(NULL, NULL, 0, NULL, cursor, type_info);
}

static enum proto_parse_status tds_prelogin(struct cursor *cursor, struct sql_proto_info *info, bool is_client)
{
    SLOG(LOG_DEBUG, "Parsing PRE-LOGIN from %s", is_client ? "client" : "server");
    assert(info->msg_type == SQL_STARTUP);
    enum proto_parse_status status = PROTO_PARSE_ERR;

    // all option offsets are relative to this address (start of msg):
    uint8_t const *msg_start = cursor->head;
    uint8_t const *msg_end = cursor->head + cursor->cap_len;    // at most
    while (1) {
        // Read next option + fetch its data
        CHECK(1);
        enum tds_msg_pl_option_token token = cursor_read_u8(cursor);
        if (token == TDS_TERMINATOR) {
            SLOG(LOG_DEBUG, "Found option terminator");
            status = PROTO_OK;
            break;
        }
        CHECK(4);
        size_t offset = cursor_read_u16n(cursor);
        size_t size = cursor_read_u16n(cursor);
        SLOG(LOG_DEBUG, "Found %s, at offset %zu, size %zu", tds_msg_prelogin_token_2_str(token), offset, size);
        struct cursor value;
        cursor_ctor(&value, msg_start + offset, size);
        // Sanity checks
        if (size > 0) {
            if (value.head <= cursor->head || /* <= since we have not read the terminator yet */
                value.head + value.cap_len > msg_end) break;
        }
        // Read value
        switch (token) {
            case TDS_VERSION:   // fetch version
                if (size != 6) return PROTO_PARSE_ERR;
                info->version_maj = cursor_read_u8(&value);
                info->version_min = cursor_read_u8(&value);
                // The rest of version 'string' is not important
                info->set_values |= SQL_VERSION;
                break;
            case TDS_ENCRYPTION:
                if (size != 1) return PROTO_PARSE_ERR;
                // See MS-TDS 2.2.6.4
                switch (*value.head) {
                    case TDS_ENCRYPT_REQ:
                    case TDS_ENCRYPT_ON:
                        info->u.startup.ssl_request = SQL_SSL_REQUESTED;
                        info->set_values |= SQL_SSL_REQUEST;
                        break;
                    case TDS_ENCRYPT_OFF:
                    case TDS_ENCRYPT_NOT_SUP:
                        break;
                    default:
                        SLOG(LOG_DEBUG, "Unknown prelogin option token %d, skipping packet", token);
                        return PROTO_PARSE_ERR;
                }
                break;
            default:
                SLOG(LOG_DEBUG, "Skipping token...");
                break;
        }
    }

    return status;
}

// TODO: one day, take into account option_flag_1 to decode EBCDIC and whether unicode chars are LE or BE?
static enum proto_parse_status extract_string(char *dst, size_t dst_size, struct cursor *cursor, uint8_t const *msg_start, uint8_t const *msg_end)
{
    // We must read offset then length (LE)
    CHECK(4);
    size_t offset = cursor_read_u16le(cursor);
    size_t size = cursor_read_u16le(cursor);
    // Sanity check
    if (size > 0) {
        if ((ssize_t)offset < cursor->head - msg_start ||
            msg_start + offset + size > msg_end) return PROTO_PARSE_ERR;
    }
    SLOG(LOG_DEBUG, "Extracting a string of size %zu", size);
    if (size > dst_size-1) size = dst_size-1;   // so we will have space for the nul byte to terminate the string
    // Read the string as UNICODE into ASCII
    while (size -- > 0) *dst ++ = msg_start[offset++];
    *dst = '\0';

    return PROTO_OK;
}

static enum proto_parse_status tds_login7(struct tds_msg_parser *tds_msg_parser, struct cursor *cursor, struct sql_proto_info *info)
{
    SLOG(LOG_DEBUG, "Parsing LOGIN7");
    assert(info->msg_type == SQL_STARTUP);

    // all option offsets are relative to this address (start of msg):
    uint8_t const *msg_start = cursor->head;
    uint8_t const *msg_end = cursor->head + cursor->cap_len;    // at most

    /* Login requests starts with many several fixed size fields,
     * first of which being the total length. Other interresting
     * fields include:
     * - OptionFlag1, which tells if client speak BE or LE, ASCII or EBCDIC,
     * and so on,
     * - UserName, Password, ServerName for the sql_startup infos
     * We skip everything else.
     * */
    CHECK(4);
    size_t length = cursor_read_u32le(cursor);
    if (length < 36 || (ssize_t)length > msg_end-msg_start) return PROTO_PARSE_ERR;
    // Note: no offset+len will be allowed after length

    // Go for OptionFlag1
    CHECK(21);
    cursor_drop(cursor, 20);
    tds_msg_parser->option_flag_1 = cursor_read_u8(cursor);

    // Go for UserName
    CHECK(15);
    enum proto_parse_status status;
    cursor_drop(cursor, 11 + 4 /* Skip HostName */);
    if (PROTO_OK != (status = extract_string(info->u.startup.user, sizeof(info->u.startup.user), cursor, msg_start, msg_end))) return status;
    info->set_values |= SQL_USER;
    // Password
    if (PROTO_OK != (status = extract_string(info->u.startup.passwd, sizeof(info->u.startup.passwd), cursor, msg_start, msg_end))) return status;
    // TODO: unscramble it
    info->set_values |= SQL_PASSWD;
    // DBNAME
    CHECK(4);
    cursor_drop(cursor, 4 /* Skip AppName */);
    if (PROTO_OK != (status = extract_string(info->u.startup.dbname, sizeof(info->u.startup.dbname), cursor, msg_start, msg_end))) return status;
    info->set_values |= SQL_DBNAME;

    SLOG(LOG_DEBUG, "LOGIN7 with user=%s, passwd=%s, dbname=%s", info->u.startup.user, info->u.startup.passwd, info->u.startup.dbname);

    return status;
}

static enum proto_parse_status skip_all_headers(struct cursor *cursor)
{
    SLOG(LOG_DEBUG, "Parsing ALL_HEADERS");

    CHECK(4);
    // Peek the length (as we are not certain the header is actually present or not)
    uint_least32_t tot_len = cursor_read_u32le(cursor);
    /* These headers are not always present.
     * The specs says:
     * "Stream headers MUST be present only in the first packet of requests", which is
     * unclear. In practice, it seams these headers are sometime absent of single packet
     * requests.
     * See wireshark TDS parser implementation, packet-tds.c(dissect_tds_all_headers).
     * We use the same heuristic here. */
    if (tot_len > 0x100) {
        SLOG(LOG_DEBUG, "ALL_HEADERS seems to be absent...");
        cursor_rollback(cursor, 4);
        return PROTO_OK;
    }

    if (tot_len < 4) return PROTO_PARSE_ERR;
    CHECK(tot_len - 4);

    cursor_drop(cursor, tot_len - 4);
    return PROTO_OK;
}

static enum proto_parse_status tds_sql_batch(struct tds_msg_parser const *tds_msg_parser, struct cursor *cursor,
        struct sql_proto_info *info)
{
    SLOG(LOG_DEBUG, "Parsing SQL-Batch");
    assert(info->msg_type == SQL_QUERY);

    // Parse ALL_HEADERS header
    enum proto_parse_status status = skip_all_headers(cursor);
    if (status != PROTO_OK) return status;

    size_t const sql_size = cursor->cap_len;
    if (sql_size & 1) {
        SLOG(LOG_DEBUG, "Dubious SQL string length %zu", sql_size);
        return PROTO_PARSE_ERR;
    }
    CHECK(sql_size);
    size_t dst_pos = 0;
    append_from_unicode(tds_msg_parser, info->u.query.sql, sizeof(info->u.query.sql), &dst_pos, cursor, sql_size);
    info->set_values |= SQL_SQL;

    return PROTO_OK;
}

// read ParamMetaData and write param name+value in dst (sql string)
static enum proto_parse_status rpc_parameter_data(struct tds_msg_parser const *tds_msg_parser, char *dst, size_t dst_size, size_t *dst_pos, struct cursor *cursor)
{
    SLOG(LOG_DEBUG, "Parsing RPCParameterData");
    enum proto_parse_status status;

    // Fetch Parameter name
    if (PROTO_OK != (status = append_b_varchar(tds_msg_parser, dst, dst_size, dst_pos, cursor, "?"))) return status;
    CHECK(1);
    uint8_t status_flag = cursor_read_u8(cursor);
    SLOG(LOG_DEBUG, "Status Flag: %"PRIu8, status_flag);
#   define BY_REF_VALUE 0x01
#   define DEFAULT_VALUE 0x02
    append_string(dst, dst_size, dst_pos, status_flag & BY_REF_VALUE ? "*=":"=");

    struct type_info type_info;
    if (PROTO_OK != (status = parse_type_info(tds_msg_parser, cursor, &type_info))) return status;
    SLOG(LOG_DEBUG, "Parsed type info :%s", type_info_2_str(&type_info));

    return parse_type_info_value(tds_msg_parser, dst, dst_size, dst_pos, cursor, &type_info);
}

static enum proto_parse_status rpc_req_batch(struct tds_msg_parser const *tds_msg_parser, struct cursor *cursor, struct sql_proto_info *info)
{
    enum proto_parse_status status;

    // NameLenProcID
    CHECK(2);
    size_t name_len = cursor_peek_u16le(cursor, 0);
    SLOG(LOG_DEBUG, "NameLenProc len=%zu", name_len);
    size_t sql_len = 0;
    if (name_len == 0xffff) {
        cursor_drop(cursor, 2);
        // well known procedure name
        CHECK(2);
        unsigned const proc_id = cursor_read_u16le(cursor);
        char const *name = NULL;
        switch (proc_id) {
            case  1: name = "Cursor"; break;
            case  2: name = "CursorOpen"; break;
            case  3: name = "CursorPrepare"; break;
            case  4: name = "CursorExecute"; break;
            case  5: name = "CursorPrepExec"; break;
            case  6: name = "CursorUnprepare"; break;
            case  7: name = "CursorFetch"; break;
            case  8: name = "CursorOption"; break;
            case  9: name = "CursorClose"; break;
            case 10: name = "ExecuteSql"; break;
            case 11: name = "Prepare"; break;
            case 12: name = "Execute"; break;
            case 13: name = "PrepExec"; break;
            case 14: name = "PrepExecRpc"; break;
            case 15: name = "Unprepare"; break;
            default:
                SLOG(LOG_DEBUG, "Unknown well-known procedure id: %u", proc_id);
                return PROTO_PARSE_ERR;
        }
        int len = snprintf(info->u.query.sql, sizeof(info->u.query.sql), "%s", name);
        if (len < 0) return PROTO_PARSE_ERR;    // ?
        sql_len += len;
        info->set_values |= SQL_SQL;
    } else {
        // name as us_varchar
        info->u.query.sql[0] = '\0';    // for the debug strings
        if (PROTO_OK != (status = append_us_varchar(tds_msg_parser, info->u.query.sql,
                        sizeof(info->u.query.sql), &sql_len, cursor)))
            return status;

        info->set_values |= SQL_SQL;
    }

    // Skip OptionFlags (3 flags on 16 bits)
    CHECK(2);
    cursor_drop(cursor, 2);

    append_string(info->u.query.sql, sizeof(info->u.query.sql), &sql_len, "(");

    bool first = true;
    while (! cursor_is_empty(cursor)) {
        uint8_t const next_byte = cursor->head[0];
        if (next_byte == 0x80 || next_byte >= 0xfe) break;    // end of ParameterData
        if (first) {
            first = false;
        } else {
            append_string(info->u.query.sql, sizeof(info->u.query.sql), &sql_len, ",");
        }
        if (PROTO_OK != (status = rpc_parameter_data(tds_msg_parser, info->u.query.sql,
                        sizeof(info->u.query.sql), &sql_len, cursor))) return status;
    }

    append_string(info->u.query.sql, sizeof(info->u.query.sql), &sql_len, ")");

    return PROTO_OK;
}

static enum proto_parse_status rpc_flags(struct cursor *cursor)
{
    if (cursor_is_empty(cursor)) return PROTO_OK;   // last flags are optional
    uint8_t flag = cursor_read_u8(cursor);
    if (flag != 0x80 && flag != 0xff && flag != 0xfe) return PROTO_PARSE_ERR;
    return PROTO_OK;
}

static enum proto_parse_status tds_rpc(struct tds_msg_parser const *tds_msg_parser, struct cursor *cursor, struct sql_proto_info *info)
{
    SLOG(LOG_DEBUG, "Parsing RPC");
    assert(info->msg_type == SQL_QUERY);

    enum proto_parse_status status = skip_all_headers(cursor);
    if (status != PROTO_OK) return status;

    // There are several RPCReqBatch+Flags in the message
    while (! cursor_is_empty(cursor)) {
        if (PROTO_OK != (status = rpc_req_batch(tds_msg_parser, cursor, info))) return status;
        if (PROTO_OK != (status = rpc_flags(cursor))) return status;
    }

    return status;
}

static void add_rows(struct sql_proto_info *info, unsigned count)
{
    if (info->set_values & SQL_NB_ROWS) {
        info->u.query.nb_rows += count;
    } else {
        info->set_values |= SQL_NB_ROWS;
        info->u.query.nb_rows = count;
    }
}

static void add_fields(struct sql_proto_info *info, unsigned count)
{
    if (info->set_values & SQL_NB_FIELDS) {
        info->u.query.nb_fields += count;
    } else {
        info->set_values |= SQL_NB_FIELDS;
        info->u.query.nb_fields = count;
    }
}

static enum proto_parse_status tds_parse_env_change(struct tds_msg_parser *tds_msg_parser, struct cursor *cursor,
        struct sql_proto_info *info)
{
    CHECK(4);
    size_t length = cursor_read_u16le(cursor);
    SLOG(LOG_DEBUG, "Parsing Env change of length %zu", length);
    CHECK(length);
    enum env_change_token env_token = cursor_read_u8(cursor);
    SLOG(LOG_DEBUG, "Parsing environnement change of type %s", env_change_token_2_str(env_token));
    enum proto_parse_status status;
    switch (env_token) {
        case ENV_DATABASE:
            {
                size_t len = 0;
                status = append_b_varchar(tds_msg_parser, info->u.startup.dbname,
                        sizeof(info->u.startup.dbname), &len, cursor, "?");
                if (status != PROTO_OK) return status;
                info->set_values |= SQL_DBNAME;
                if (PROTO_OK != (status = skip_b_varchar(cursor))) return status;
            }
            break;
        case ENV_CHARACTER_SET:
            {
                size_t len = 0;
                char *buf = tempstr();
                status = append_b_varchar(tds_msg_parser, buf,
                        TEMPSTR_SIZE, &len, cursor, "?");
                if (status != PROTO_OK) return status;
                if (0 == strcmp("ISO-8859-1", buf)) {
                    info->u.startup.encoding = SQL_ENCODING_LATIN1;
                } else if (0 == strcmp("UTF8", buf)) {
                    info->u.startup.encoding = SQL_ENCODING_UTF8;
                } else {
                    SLOG(LOG_DEBUG, "Unknown encoding %s", buf);
                    info->u.startup.encoding = SQL_ENCODING_UNKNOWN;
                }
                info->set_values |= SQL_ENCODING;
                if (PROTO_OK != (status = skip_b_varchar(cursor))) return status;
            }
            break;
        default:
            {
                // Env change type was already swallowed
                cursor_drop(cursor, length - 1);
            }
            break;
    }
    return PROTO_OK;
}

// Parse a single token from a TDS result message
static enum proto_parse_status tds_result_token(struct tds_msg_parser *tds_msg_parser, struct cursor *cursor, struct sql_proto_info *info, bool *skip)
{
    CHECK(1);
    enum tds_msg_token tok = cursor_read_u8(cursor);
    SLOG(LOG_DEBUG, "Parsing Result Token %s", tds_msg_token_2_str(tok));

    enum proto_parse_status status;

    switch (tok) {
        case DONE_TOKEN:
        case DONEPROC_TOKEN:
        case DONEINPROC_TOKEN:
            {
                CHECK(8);
#               define DONE_MORE       0x001
#               define DONE_ERROR      0x002
#               define DONE_INXACT     0x004
#               define DONE_COUNT_SET  0x010
#               define DONE_ATTN       0x020
#               define DONE_RPCINBATCH 0x080
#               define DONE_SRVERROR   0x100
                uint_least16_t const msg_status = cursor_read_u16le(cursor);
                // Current command
                cursor_drop(cursor, 2);
                // Only 32 bits prior to TDS 7.2. Sometime mixed? :-/
                // If 32 bits are left, assume the last rowcount is 32 bits
                uint_least64_t rowcount;
                SLOG(LOG_DEBUG, "Got %s 7.2, reading %d bytes", tds_msg_parser->pre_7_2 ? "pre": "post",
                    tds_msg_parser->pre_7_2 ? 4: 8);
                if (tds_msg_parser->pre_7_2 || cursor->cap_len == 4) {
                    CHECK(4);
                    rowcount = cursor_read_u32le(cursor);
                } else {
                    CHECK(8);
                    rowcount = cursor_read_u64le(cursor);
                }
                if (msg_status & DONE_COUNT_SET) {
                    SLOG(LOG_DEBUG, "Got %zu rows", rowcount);
                    info->set_values |= SQL_NB_ROWS;
                    info->u.query.nb_rows = rowcount;
                }
                if (! (msg_status & DONE_MORE)) {
                    // done with query
                    info->set_values |= SQL_REQUEST_STATUS;
                    info->request_status = (msg_status & DONE_ERROR) ? SQL_REQUEST_ERROR : SQL_REQUEST_COMPLETE;
                }
            }
            break;
        case ERROR_TOKEN:
            {
                CHECK(2);
                size_t const tot_len = cursor_read_u16le(cursor);
                if (tot_len < 15) return PROTO_PARSE_ERR;
                CHECK(tot_len);
                // We are only interested in error code and error message
                // We copy our cursor and drop tot_len from the main cursor
                struct cursor value = *cursor;
                cursor_drop(cursor, tot_len);
                if (info->set_values & SQL_ERROR_CODE) {
                    // Only take first error code / error msg
                    break;
                }
                uint_least32_t const error_code = cursor_read_u32le(&value);
                info->set_values |= SQL_REQUEST_STATUS;
                info->request_status = SQL_REQUEST_ERROR;
                info->set_values |= SQL_ERROR_CODE;
                snprintf(info->error_code, sizeof(info->error_code), "%d", error_code);
                // Status (1 byte) + classe (1 byte)
                cursor_drop(&value, 2);
                size_t len = 0;
                append_us_varchar(tds_msg_parser, info->error_message, sizeof(info->error_message), &len, &value);
                info->set_values |= SQL_ERROR_MESSAGE;
            }
            break;
        case RETURNSTATUS_TOKEN:
            {
                CHECK(4);
                cursor_drop(cursor, 4);
            }
            break;
        case RETURNVALUE_TOKEN:
            {
                // skip parameter ordinal
                CHECK(2);
                cursor_drop(cursor, 2);
                // Skip parameter name
                if (PROTO_OK != (status = skip_b_varchar(cursor))) return status;
                // status flag  1 byte
                // user type    2 / 4 bytes
                // Flags        2 bytes
                unsigned skip_bytes = 1 + (tds_msg_parser->pre_7_2 ? 2:4) + 2;
                CHECK(skip_bytes);
                cursor_drop(cursor, skip_bytes);
                // Type info
                struct type_info type_info;
                if (PROTO_OK != (status = parse_type_info(tds_msg_parser, cursor, &type_info))) return status;
                // Type info Value
                skip_type_info_value(cursor, &type_info);
            }
            break;
        case COLMETADATA_TOKEN:
            {
                info->msg_type = SQL_QUERY;
                // We must fetch the data size for next row
                CHECK(2);
                unsigned count = cursor_read_u16le(cursor); // missing from specs but actually present (and required)
#               define NO_METADATA 0xffffU
                if (NO_METADATA == count) break;
                SLOG(LOG_DEBUG, "Parsing COLMETADATA with %u columns", count);
                add_fields(info, count);
                tds_msg_parser->column_count = count;
                if (tds_msg_parser->column_count >= MAX_TYPE_INFO) {
                    SLOG(LOG_DEBUG, "Too much column to parse (%d)", tds_msg_parser->column_count);
                    return PROTO_PARSE_ERR;
                }

                if (!tds_msg_parser->pre_7_2) {
                    CHECK(6);
                    // Small heuristic to guess if we are really post 7.2
                    enum type_info_token token_pre_7_2 = cursor_peek_u8(cursor, 4);
                    enum type_info_token token_post_7_2 = cursor_peek_u8(cursor, 6);
                    if (is_type_info_token(token_pre_7_2) && !is_type_info_token(token_post_7_2)) {
                        SLOG(LOG_DEBUG, "Looks like colmetadata token is pre 7.2");
                        tds_msg_parser->pre_7_2 = true;
                    }
                }
                for (unsigned i = 0; i < count; i++) {
                    SLOG(LOG_DEBUG, "Parsing column metadata %u/%u", i, count);
                    size_t flag_length = (tds_msg_parser->pre_7_2 ? 2:4) + 2;
                    CHECK(flag_length);
                    SLOG(LOG_DEBUG, "Dropping user type and flag");
                    cursor_drop(cursor, flag_length);
                    struct type_info *type_info = NULL;
                    if (i < MAX_TYPE_INFO) {
                        type_info = tds_msg_parser->type_info + i;
                    }
                    if (PROTO_OK != (status = parse_type_info(tds_msg_parser, cursor, type_info))) return status;
                    SLOG(LOG_DEBUG, "Column has type %s", type_info_token_2_str(type_info->token));

                    // Skip colname
                    // FIXME: we may have a tablename here for text, ntext and image columns, for some reason
                    if (PROTO_OK != (status = skip_b_varchar(cursor))) return status;
                }
            }
            break;
        case ROW_TOKEN:
            {
                info->msg_type = SQL_QUERY;
                if (tds_msg_parser->column_count > MAX_TYPE_INFO - 1) {
                    SLOG(LOG_DEBUG, "Too much column to process (%d)", tds_msg_parser->column_count);
                    return PROTO_PARSE_ERR;
                }
                for (unsigned i = 0; i < tds_msg_parser->column_count; i++) {
                    SLOG(LOG_DEBUG, "Reading column %u/%u", i, tds_msg_parser->column_count);
                    skip_type_info_value(cursor, tds_msg_parser->type_info + i);
                }
                add_rows(info, 1);
                SLOG(LOG_DEBUG, "Incremented row count to %u", info->u.query.nb_rows);
            }
            break;
        case LOGINACK_TOKEN:
            {   // Here we get the protocol version that we are going to use (we are interested to know if we run below or above 7.2)
                info->msg_type = SQL_STARTUP;
                CHECK(2);
                size_t length = cursor_read_u16le(cursor);
                SLOG(LOG_DEBUG, "Parsing LOGINACK of length %zu", length);
                if (length < 10) return PROTO_PARSE_ERR;
                CHECK(length);
                cursor_drop(cursor, 1); // INTERFACE
                uint_least32_t version = cursor_read_u32n(cursor);
                info->set_values |= SQL_VERSION;
                // This protocol is so stupid...
                switch (version) {
                    case 0x07000000:
                        info->version_maj = 7;
                        info->version_min = 0;
                        break;
                    case 0x07010000:
                        info->version_maj = 7;
                        info->version_min = 1;
                        break;
                    default:
                        info->version_maj = version >> 28;
                        info->version_min = (version >> 24) & 0xf;
                        break;
                }
                tds_msg_parser->pre_7_2 = !(info->version_maj >= 7 && info->version_min >= 2);
                SLOG(LOG_DEBUG, "Version set to %u.%u (%s 7.2)", info->version_maj, info->version_min,
                        tds_msg_parser->pre_7_2 ? "pre":"post");
                // ignore the rest
                cursor_drop(cursor, length - 5);
            }
            break;
        case INFO_TOKEN:
            {
                CHECK(2);
                size_t length = cursor_read_u16le(cursor);
                CHECK(length);
                cursor_drop(cursor, length);
            }
            break;
        case ENV_CHANGE_TOKEN:
            {
                return tds_parse_env_change(tds_msg_parser, cursor, info);
            }
        case ORDER_TOKEN:
            {
                CHECK(2);
                size_t length = cursor_read_u16le(cursor);
                CHECK(length);
                cursor_drop(cursor, length);
            }
            break;
        default:
            {
                SLOG(LOG_DEBUG, "Don't know how to handle result token %s, skipping message", tds_msg_token_2_str(tok));
                *skip = true;
            }
            break;
    }

    return PROTO_OK;
}

static enum sql_msg_type sql_msg_type_of_tds_msg(enum tds_packet_type type, enum tds_packet_type last_packet_type)
{
    switch (type) {
        case TDS_PKT_TYPE_SQL_BATCH:
        case TDS_PKT_TYPE_RPC:
        case TDS_PKT_TYPE_BULK_LOAD:
            return SQL_QUERY;
        case TDS_PKT_TYPE_SSPI:
        case TDS_PKT_TYPE_PRELOGIN:
        case TDS_PKT_TYPE_LOGIN:
        case TDS_PKT_TYPE_TDS7_LOGIN:
            return SQL_STARTUP;
        case TDS_PKT_TYPE_ATTENTION:
        case TDS_PKT_TYPE_MANAGER_REQ:
            return SQL_UNKNOWN;
        case TDS_PKT_TYPE_RESULT:
            /* Here we go: all msgs from server to clients are "result", which meaning depends on when it's encountered
             * To sort this out we merely keep the last msg type from client to server and copy it for the response. */
            return sql_msg_type_of_tds_msg(last_packet_type, 0);
    }
    return SQL_UNKNOWN;
}

// return the direction for client->server
static unsigned c2s_way_of_tds_msg_type(enum tds_packet_type type, unsigned current_way)
{
    switch (type) {
        case TDS_PKT_TYPE_SQL_BATCH:
        case TDS_PKT_TYPE_LOGIN:
        case TDS_PKT_TYPE_RPC:
        case TDS_PKT_TYPE_ATTENTION:
        case TDS_PKT_TYPE_BULK_LOAD:
        case TDS_PKT_TYPE_MANAGER_REQ:
        case TDS_PKT_TYPE_TDS7_LOGIN:
        case TDS_PKT_TYPE_SSPI:
        case TDS_PKT_TYPE_PRELOGIN:
            return current_way;
        case TDS_PKT_TYPE_RESULT:
            return !current_way;
    }
    return current_way; // in doubt, first packet is probably from client
}

static enum proto_parse_status tds_msg_parse_result(struct tds_msg_parser *tds_msg_parser, struct cursor *cursor,
        struct sql_proto_info *info)
{
    SLOG(LOG_DEBUG, "Parsing Result");
    enum proto_parse_status status;
    switch (tds_msg_parser->last_pkt_type) {
        case TDS_PKT_TYPE_PRELOGIN:
            return tds_prelogin(cursor, info, false);
        default:
            while (! cursor_is_empty(cursor)) {
                bool skip = false;
                status = tds_result_token(tds_msg_parser, cursor, info, &skip);
                SLOG(LOG_DEBUG, "Token parse has returned %s", proto_parse_status_2_str(status));
                if (status != PROTO_OK) break;
                if (skip) break;
            }
            return status;
    }
}

static enum proto_parse_status tds_msg_sbuf_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct tds_msg_parser *tds_msg_parser = DOWNCAST(parser, parser, tds_msg_parser);

    // Retrieve TDS infos
    ASSIGN_INFO_CHK(tds, parent, PROTO_PARSE_ERR);
    bool has_gap = wire_len > cap_len;

    // If this is the first time we are called, init c2s_way
    if (tds_msg_parser->c2s_way == UNSET) {
        tds_msg_parser->c2s_way = c2s_way_of_tds_msg_type(tds->type, way);
        SLOG(LOG_DEBUG, "First packet, init c2s_way to %u", tds_msg_parser->c2s_way);
    }

    // Immediatly parse on first gap, else, bufferize
    if (!tds_msg_parser->had_gap && !has_gap && ((tds->status & TDS_EOM) == 0x00)) {
        SLOG(LOG_DEBUG, "Packet is not an EOM, buffering it");
        streambuf_set_restart(&tds_msg_parser->sbuf, way, payload, true);
        return PROTO_OK;
    }

    // Now build the proto_info
    struct sql_proto_info info;
    proto_info_ctor(&info.info, parser, parent, wire_len, 0);
    info.is_query = way == tds_msg_parser->c2s_way;
    info.msg_type = sql_msg_type_of_tds_msg(tds->type, tds_msg_parser->last_pkt_type);
    SLOG(LOG_DEBUG, "msg type = %s (TDS type = %s, last TDS type = %s)", sql_msg_type_2_str(info.msg_type),
            tds_packet_type_2_str(tds->type), tds_packet_type_2_str(tds_msg_parser->last_pkt_type));
    if (info.is_query) tds_msg_parser->last_pkt_type = tds->type;
    info.set_values = 0;

    struct cursor cursor;
    cursor_ctor(&cursor, payload, cap_len);

    enum proto_parse_status status = PROTO_PARSE_ERR;

    switch (tds->type) {
        case TDS_PKT_TYPE_TDS7_LOGIN:
            status = tds_login7(tds_msg_parser, &cursor, &info);
            break;
        case TDS_PKT_TYPE_SQL_BATCH:
            status = tds_sql_batch(tds_msg_parser, &cursor, &info);
            break;
        case TDS_PKT_TYPE_RPC:
            status = tds_rpc(tds_msg_parser, &cursor, &info);
            break;
        case TDS_PKT_TYPE_RESULT:
            status = tds_msg_parse_result(tds_msg_parser, &cursor, &info);
            break;
        case TDS_PKT_TYPE_LOGIN:
        case TDS_PKT_TYPE_ATTENTION:
        case TDS_PKT_TYPE_BULK_LOAD:
        case TDS_PKT_TYPE_MANAGER_REQ:
        case TDS_PKT_TYPE_SSPI:
            SLOG(LOG_DEBUG, "Don't know how to parse a TDS msg of type %s", tds_packet_type_2_str(tds->type));
            status = PROTO_OK;
            break;
        case TDS_PKT_TYPE_PRELOGIN:
            status = tds_prelogin(&cursor, &info, true);
            break;
    }
    SLOG(LOG_DEBUG, "Finished parsing %s, status = %s", tds_packet_type_2_str(tds->type), proto_parse_status_2_str(status));

    tds_msg_parser->had_gap = has_gap && !(tds->status & TDS_EOM);

    // Advertise the parsed packet even if an error has occured
    return proto_parse(NULL, &info.info, way, payload, cap_len, wire_len, now, tot_cap_len, tot_packet);
}

static enum proto_parse_status tds_msg_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *payload, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct tds_msg_parser *tds_msg_parser = DOWNCAST(parser, parser, tds_msg_parser);

    enum proto_parse_status const status = streambuf_add(&tds_msg_parser->sbuf, parser, parent, way,
            payload, cap_len, wire_len, now, tot_cap_len, tot_packet);

    return status;
}

/*
 * Construction/Destruction
 */

static struct proto proto_tds_msg_;
struct proto *proto_tds_msg = &proto_tds_msg_;

void tds_msg_init(void)
{
    static struct proto_ops const ops = {
        .parse       = tds_msg_parse,
        .parser_new  = tds_msg_parser_new,
        .parser_del  = tds_msg_parser_del,
        .info_2_str  = sql_info_2_str,
        .info_addr   = sql_info_addr
    };
    proto_ctor(&proto_tds_msg_, &ops, "TDS(msg)", PROTO_CODE_TDS_MSG);
}

void tds_msg_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    proto_dtor(&proto_tds_msg_);
#   endif
}
