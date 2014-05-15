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

#include <iconv.h>
#include "junkie/proto/cifs.h"
#include "junkie/tools/objalloc.h"
#include "junkie/proto/cursor.h"
#include "junkie/proto/tcp.h"

#undef LOG_CAT
#define LOG_CAT proto_cifs_log_category

LOG_CATEGORY_DEF(proto_cifs);

#define CIFS_HEADER_SIZE sizeof(struct cifs_hdr)

static char const *smb_command_2_str(enum smb_command command)
{
    switch (command) {
        case SMB_COM_CREATE_DIRECTORY       : return "SMB_COM_CREATE_DIRECTORY";
        case SMB_COM_DELETE_DIRECTORY       : return "SMB_COM_DELETE_DIRECTORY";
        case SMB_COM_OPEN                   : return "SMB_COM_OPEN";
        case SMB_COM_CREATE                 : return "SMB_COM_CREATE";
        case SMB_COM_CLOSE                  : return "SMB_COM_CLOSE";
        case SMB_COM_FLUSH                  : return "SMB_COM_FLUSH";
        case SMB_COM_DELETE                 : return "SMB_COM_DELETE";
        case SMB_COM_RENAME                 : return "SMB_COM_RENAME";
        case SMB_COM_QUERY_INFORMATION      : return "SMB_COM_QUERY_INFORMATION";
        case SMB_COM_SET_INFORMATION        : return "SMB_COM_SET_INFORMATION";
        case SMB_COM_READ_INFORMATION       : return "SMB_COM_READ_INFORMATION";
        case SMB_COM_WRITE_INFORMATION      : return "SMB_COM_WRITE_INFORMATION";
        case SMB_COM_LOCK_BYTE_RANGE        : return "SMB_COM_LOCK_BYTE_RANGE";
        case SMB_COM_UNLOCK_BYTE_RANGE      : return "SMB_COM_UNLOCK_BYTE_RANGE";
        case SMB_COM_CREATE_TEMPORARY       : return "SMB_COM_CREATE_TEMPORARY";
        case SMB_COM_CREATE_NEW             : return "SMB_COM_CREATE_NEW";
        case SMB_COM_CHECK_DIRECTORY        : return "SMB_COM_CHECK_DIRECTORY";
        case SMB_COM_PROCESS_EXIT           : return "SMB_COM_PROCESS_EXIT";
        case SMB_COM_SEEK                   : return "SMB_COM_SEEK";
        case SMB_COM_LOCK_AND_READ          : return "SMB_COM_LOCK_AND_READ";
        case SMB_COM_WRITE_AND_UNLOCK       : return "SMB_COM_WRITE_AND_UNLOCK";
        case SMB_COM_READ_RAW               : return "SMB_COM_READ_RAW";
        case SMB_COM_READ_MPX               : return "SMB_COM_READ_MPX";
        case SMB_COM_READ_MPX_SECONDARY     : return "SMB_COM_READ_MPX_SECONDARY";
        case SMB_COM_WRITE_RAW              : return "SMB_COM_WRITE_RAW";
        case SMB_COM_WRITE_MPX              : return "SMB_COM_WRITE_MPX";
        case SMB_COM_WRITE_MPX_SECONDARY    : return "SMB_COM_WRITE_MPX_SECONDARY";
        case SMB_COM_WRITE_COMPLETE         : return "SMB_COM_WRITE_COMPLETE";
        case SMB_COM_QUERY_SERVER           : return "SMB_COM_QUERY_SERVER";
        case SMB_COM_SET_INFORMATION2       : return "SMB_COM_SET_INFORMATION2";
        case SMB_COM_QUERY_INFORMATION2     : return "SMB_COM_QUERY_INFORMATION2";
        case SMB_COM_LOCKING_ANDX           : return "SMB_COM_LOCKING_ANDX";
        case SMB_COM_TRANSACTION            : return "SMB_COM_TRANSACTION";
        case SMB_COM_TRANSACTION_SECONDARY  : return "SMB_COM_TRANSACTION_SECONDARY";
        case SMB_COM_IOCTL                  : return "SMB_COM_IOCTL";
        case SMB_COM_IOCTL_SECONDARY        : return "SMB_COM_IOCTL_SECONDARY";
        case SMB_COM_COPY                   : return "SMB_COM_COPY";
        case SMB_COM_MOVE                   : return "SMB_COM_MOVE";
        case SMB_COM_ECHO                   : return "SMB_COM_ECHO";
        case SMB_COM_WRITE_AND_CLOSE        : return "SMB_COM_WRITE_AND_CLOSE";
        case SMB_COM_OPEN_ANDX              : return "SMB_COM_OPEN_ANDX";
        case SMB_COM_READ_ANDX              : return "SMB_COM_READ_ANDX";
        case SMB_COM_WRITE_ANDX             : return "SMB_COM_WRITE_ANDX";
        case SMB_COM_NEW_FILE_SIZE          : return "SMB_COM_NEW_FILE_SIZE";
        case SMB_COM_CLOSE_AND_TREE_DISC    : return "SMB_COM_CLOSE_AND_TREE_DISC";
        case SMB_COM_TRANSACTION2           : return "SMB_COM_TRANSACTION2";
        case SMB_COM_TRANSACTION2_SECONDARY : return "SMB_COM_TRANSACTION2_SECONDARY";
        case SMB_COM_FIND_CLOSE2            : return "SMB_COM_FIND_CLOSE2";
        case SMB_COM_FIND_NOTIFY_CLOSE      : return "SMB_COM_FIND_NOTIFY_CLOSE";
        case SMB_COM_TREE_CONNECT           : return "SMB_COM_TREE_CONNECT";
        case SMB_COM_TREE_DISCONNECT        : return "SMB_COM_TREE_DISCONNECT";
        case SMB_COM_NEGOCIATE              : return "SMB_COM_NEGOCIATE";
        case SMB_COM_SESSION_SETUP_ANDX     : return "SMB_COM_SESSION_SETUP_ANDX";
        case SMB_COM_LOGOFF_ANDX            : return "SMB_COM_LOGOFF_ANDX";
        case SMB_COM_SECURITY_PACKAGE_ANDX  : return "SMB_COM_SECURITY_PACKAGE_ANDX";
        case SMB_COM_QUERY_INFORMATION_DISK : return "SMB_COM_QUERY_INFORMATION_DISK";
        case SMB_COM_SEARCH                 : return "SMB_COM_SEARCH";
        case SMB_COM_FIND                   : return "SMB_COM_FIND";
        case SMB_COM_FIND_UNIQUE            : return "SMB_COM_FIND_UNIQUE";
        case SMB_COM_FIND_CLOSE             : return "SMB_COM_FIND_CLOSE";
        case SMB_COM_NT_TRANSACT            : return "SMB_COM_NT_TRANSACT";
        case SMB_COM_NT_TRANSACT_SECONDARY  : return "SMB_COM_NT_TRANSACT_SECONDARY";
        case SMB_COM_NT_CREATE_ANDX         : return "SMB_COM_NT_CREATE_ANDX";
        case SMB_COM_NT_CANCEL              : return "SMB_COM_NT_CANCEL";
        case SMB_COM_NT_RENAME              : return "SMB_COM_NT_RENAME";
        case SMB_COM_OPEN_PRINT_FILE        : return "SMB_COM_OPEN_PRINT_FILE";
        case SMB_COM_WRITE_PRINT_FILE       : return "SMB_COM_WRITE_PRINT_FILE";
        case SMB_COM_CLOSE_PRINT_FILE       : return "SMB_COM_CLOSE_PRINT_FILE";
        case SMB_COM_GET_PRINT_FILE         : return "SMB_COM_GET_PRINT_FILE";
        case SMB_COM_READ_BULK              : return "SMB_COM_READ_BULK";
        case SMB_COM_WRITE_BULK             : return "SMB_COM_WRITE_BULK";
        case SMB_COM_WRITE_BULK_DATA        : return "SMB_COM_WRITE_BULK_DATA";
        case SMB_COM_INVALID                : return "SMB_COM_INVALID";
        case SMB_COM_NO_ANDX_COMMAND        : return "SMB_COM_NO_ANDX_COMMAND";
        default                             : return tempstr_printf("Unknown smb command %d", command);
    }
}

struct cifs_hdr {
    uint32_t code;      // Must contains 0xff 'SMB'
    uint8_t command;
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

/*
 * Cursor functions
 */

int cursor_copy_string(struct cursor *cursor, size_t max_src, char *buf, size_t buf_size)
{
    assert(buf);
    uint8_t marker[1] = {0x00};
    int str_len = cursor_lookup_marker(cursor, marker, sizeof marker, max_src);
    if (str_len < 0) return -1;
    size_t str_size = str_len + sizeof marker;
    int copied_bytes = MIN(str_size, buf_size);
    cursor_copy(buf, cursor, copied_bytes);
    if (buf_size < str_size)
        cursor_drop(cursor, str_size - buf_size);
    return str_len;
}

int cursor_copy_utf16(struct cursor *cursor, iconv_t cd, size_t max_src, char *buf, size_t buf_size)
{
    assert(buf);
    char marker[2] = {0x00, 0x00};
    int str_len = cursor_lookup_marker(cursor, marker, sizeof marker, max_src);
    if (str_len < 0) return -1;
    uint8_t const *src = cursor->head;
    size_t str_size = str_len + sizeof marker;
    iconv(cd, (char **)&src, &str_size, &buf, &buf_size);
    cursor_drop(cursor, str_size);
    return str_size;
}

/*
 * Parser
 */

static pthread_key_t iconv_pthread_key;

static iconv_t get_iconv()
{
    iconv_t iconv_cd = pthread_getspecific(iconv_pthread_key);
    if (iconv_cd == NULL) {
        iconv_cd = iconv_open("UTF8//IGNORE", "UTF16LE");
        assert(iconv_cd != (iconv_t)-1);
        pthread_setspecific(iconv_pthread_key, (void *)iconv_cd);
    }
    return iconv_cd;
}

struct cifs_parser {
    struct parser parser;
    bool unicode;
};

static int cifs_parser_ctor(struct cifs_parser *cifs_parser, struct proto *proto)
{
    SLOG(LOG_DEBUG, "Constructing cifs_parser@%p", cifs_parser);
    assert(proto == proto_cifs);
    if (0 != parser_ctor(&cifs_parser->parser, proto)) return -1;
    cifs_parser->unicode = true;
    return 0;
}

static struct parser *cifs_parser_new(struct proto *proto)
{
    struct cifs_parser *cifs_parser = objalloc_nice(sizeof(*cifs_parser), "cifs parsers");
    if (! cifs_parser) return NULL;
    if (-1 == cifs_parser_ctor(cifs_parser, proto)) {
        objfree(cifs_parser);
        return NULL;
    }
    return &cifs_parser->parser;
}

static void cifs_parser_dtor(struct cifs_parser *cifs_parser)
{
    SLOG(LOG_DEBUG, "Destructing cifs_parser@%p", cifs_parser);
    parser_dtor(&cifs_parser->parser);
}

static void cifs_parser_del(struct parser *parser)
{
    struct cifs_parser *cifs_parser = DOWNCAST(parser, parser, cifs_parser);
    cifs_parser_dtor(cifs_parser);
    objfree(cifs_parser);
}

/*
 * Parse functions
 */

static void const *cifs_info_addr(struct proto_info const *info_, size_t *size)
{
    struct cifs_proto_info const *info = DOWNCAST(info_, info, cifs_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *cifs_info_2_str(struct proto_info const *info_)
{
    struct cifs_proto_info const *info = DOWNCAST(info_, info, cifs_proto_info);
    char *str = tempstr_printf("%s, command=%s, status=0x%08"PRIx32,
            proto_info_2_str(info_),
            smb_command_2_str(info->command),
            info->status);
    return str;
}

static int packet_is_cifs(struct cifs_hdr const *cifshdr)
{
    return READ_U32N(&cifshdr->code) == 0xff534d42; // 0xff + SMB
}

static void cifs_proto_info_ctor(struct cifs_proto_info *info, struct parser *parser, struct proto_info *parent, size_t header, size_t payload, struct cifs_hdr const * cifshdr)
{
    proto_info_ctor(&info->info, parser, parent, header, payload);
    info->command = READ_U8(&cifshdr->command);
    info->status = READ_U32(&cifshdr->status);
    info->set_values = 0;
}


/*
 * Can be either uchar or unicode (utf-16le) depending on capabilities in negociate response
 * It must be 16-bit aligned.
 * @return number of read bytes from cursor
 */
int parse_smb_string(struct cifs_parser *cifs_parser, struct cursor *cursor,
        char *buf, int buf_size)
{
    int ret = 0;
    if (!cifs_parser->unicode)
        ret = cursor_copy_string(cursor, cursor->cap_len, buf, buf_size);
    else
        ret = cursor_copy_utf16(cursor, get_iconv(), cursor->cap_len, buf, buf_size);
    SLOG(LOG_DEBUG, "Parse smb string as %sunicode: %s", cifs_parser->unicode ? "" : "non-",
            ret > 0 ? buf : "error");
    return ret;
}

static void parse_capabilities(struct cifs_parser *cifs_parser, struct cursor *cursor)
{
    uint32_t capabilities = cursor_read_u32le(cursor);
    #define CAP_UNICODE 0x00000004
    cifs_parser->unicode = (capabilities & CAP_UNICODE) == CAP_UNICODE;
    SLOG(LOG_DEBUG, "Found capabilities 0x%04"PRIx16, capabilities);
}

/*
 * Negociate response:
 * Parameters
 * | UCHAR (0x11) | USHORT        | UCHAR         | USHORT      | USHORT       | ULONG         | ULONG      | ULONG      | ULONG        | 8 bytes    | USHORT         | UCHAR           |
 * | Word count   | Dialect Index | Security mode | MaxMpxCount | MaxNumberVcs | MaxBufferSize | MaxRawSize | SessionKey | Capabilities | SystemTime | ServerTimeZone | ChallengeLength |
 * Data
 * | USHORT     | <Challenge length> bytes | smb string |
 * | Byte count | Challenge                | domain     |
 */
static enum proto_parse_status parse_negociate(struct cifs_parser *cifs_parser, unsigned to_srv,
        struct cursor *cursor, struct cifs_proto_info *info)
{
    SLOG(LOG_DEBUG, "Parse of negociate to_srv: %d", to_srv);
    // We are only interested in negociate response
    if (!to_srv) return PROTO_OK;
    CHECK(0x12);
    uint8_t word_count = cursor_read_u8(cursor);
    if (0x11 != word_count) {
        SLOG(LOG_DEBUG, "Negociation response must have a word count of 0x11, got 0x%02"PRIx8, word_count);
        return PROTO_PARSE_ERR;
    }
    // Reach capabilities
    cursor_drop(cursor, 19);
    parse_capabilities(cifs_parser, cursor);

    cursor_drop(cursor, 10);
    uint8_t challenge_length = cursor_read_u8(cursor);
    uint16_t byte_count = cursor_read_u16le(cursor);
    CHECK(byte_count);
    if (challenge_length > byte_count) {
        SLOG(LOG_DEBUG, "Challenge length must be inferior to byte count (%02"PRIx8" > %02"PRIx16, challenge_length, byte_count);
        return PROTO_PARSE_ERR;
    }
    cursor_drop(cursor, challenge_length);

    if (parse_smb_string(cifs_parser, cursor, info->domain, sizeof(info->domain)) < 0)
        return PROTO_PARSE_ERR;
    info->set_values |= SMB_DOMAIN;
    SLOG(LOG_DEBUG, "Found domain %s", info->domain);

    return PROTO_OK;
}

/*
 * Session initialisation
 * Parameters
 * | UCHAR (0x0d) | UCHAR       | UCHAR        | USHORT     | USHORT        | USHORT      | USHORT   | ULONG      | USHORT         | USHORT             | ULONG    | ULONG        |
 * | Word count   | AndXCommand | AndXReserved | AndXOffset | MaxBufferSize | MaxMpxCount | VcNumber | SessionKey | OEMPasswordLen | UnicodePasswordLen | Reserved | Capabilities |
 * Data
 * | USHORT     | UCHAR         | UCHAR             | UCHAR | SMB_STRING    | SMB_STRING      | SMB_STRING | SMB_STRING     |
 * | Byte count | OEMPassword[] | UnicodePassword[] | Pad[] | AccountName[] | PrimaryDomain[] | NativeOS[] | NativeLanMan[] |
 */
static enum proto_parse_status parse_session_setup(struct cifs_parser *cifs_parser, unsigned to_srv,
        struct cursor *cursor, struct cifs_proto_info *info)
{
    if (to_srv) return PROTO_OK;
    CHECK(0x0d + 0x02);
    uint8_t word_count = cursor_read_u8(cursor);
    if (0x0d != word_count) {
        SLOG(LOG_DEBUG, "Session setup andx request must have a word count of 0x0d, got 0x%02"PRIx8, word_count);
        return PROTO_PARSE_ERR;
    }
    cursor_drop(cursor, 14);
    uint16_t oem_password_len = cursor_read_u16le(cursor);
    uint16_t unicode_password_len = cursor_read_u16le(cursor);
    cursor_drop(cursor, 4);
    parse_capabilities(cifs_parser, cursor);

    uint16_t byte_count = cursor_read_u16le(cursor);
    CHECK(byte_count);
    uint8_t padding = (oem_password_len + unicode_password_len) % 1 + 1;
    if (byte_count < (oem_password_len + unicode_password_len + padding)) {
        SLOG(LOG_DEBUG, "Byte count must be superior to passwords length (%02"PRIx8" > %02"PRIx16, byte_count, oem_password_len + unicode_password_len);
        return PROTO_PARSE_ERR;
    }
    cursor_drop(cursor, oem_password_len + unicode_password_len + padding);
    if (parse_smb_string(cifs_parser, cursor, info->user, sizeof(info->user)) < 0)
        return PROTO_PARSE_ERR;
    info->set_values |= SMB_USER;
    SLOG(LOG_DEBUG, "Found user %s", info->user);

    return PROTO_OK;
}

static enum proto_parse_status cifs_parse(struct parser *parser, struct proto_info *parent,
        unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len,
        struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    /* Sanity checks */
    if (wire_len < CIFS_HEADER_SIZE) return PROTO_PARSE_ERR;
    if (cap_len < CIFS_HEADER_SIZE) return PROTO_TOO_SHORT;

    struct cifs_hdr const *cifshdr = (struct cifs_hdr const *) packet;
    if (! packet_is_cifs(cifshdr)) {
        return PROTO_PARSE_ERR;
    }

    struct cifs_proto_info info;
    cifs_proto_info_ctor(&info, parser, parent, CIFS_HEADER_SIZE, wire_len - CIFS_HEADER_SIZE, cifshdr);

    struct cursor cursor;
    cursor_ctor(&cursor, packet + CIFS_HEADER_SIZE, cap_len - CIFS_HEADER_SIZE);

    bool to_srv = way;
    ASSIGN_INFO_OPT(tcp, parent);
    if (tcp) to_srv = tcp->to_srv;

    struct cifs_parser *cifs_parser = DOWNCAST(parser, parser, cifs_parser);

    SLOG(LOG_DEBUG, "Parse of a cifs command %s", smb_command_2_str(info.command));
    enum proto_parse_status status = PROTO_OK;
    switch (info.command) {
        case SMB_COM_SESSION_SETUP_ANDX:
            status = parse_session_setup(cifs_parser, to_srv, &cursor, &info);
            break;
        case SMB_COM_NEGOCIATE:
            status = parse_negociate(cifs_parser, to_srv, &cursor, &info);
            break;
        default:
            break;
    }
    if (status != PROTO_OK) SLOG(LOG_DEBUG, "Probleme when parsing cifs: %s", proto_parse_status_2_str(status));

    return proto_parse(NULL, &info.info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
}

static struct uniq_proto uniq_proto_cifs;
struct proto *proto_cifs = &uniq_proto_cifs.proto;

/*
 * Initialization
 */

void cifs_init(void)
{
    log_category_proto_cifs_init();

    static struct proto_ops const ops = {
        .parse      = cifs_parse,
        .parser_new = cifs_parser_new,
        .parser_del = cifs_parser_del,
        .info_2_str = cifs_info_2_str,
        .info_addr  = cifs_info_addr,
    };
    uniq_proto_ctor(&uniq_proto_cifs, &ops, "CIFS", PROTO_CODE_CIFS);
    pthread_key_create(&iconv_pthread_key, (void (*)(void *))iconv_close);
}

void cifs_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    uniq_proto_dtor(&uniq_proto_cifs);
    pthread_key_delete(iconv_pthread_key);
#   endif
    log_category_proto_cifs_fini();
}
