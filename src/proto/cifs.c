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
 * Parse
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
}


/*
 *
 */
static enum proto_parse_status parse_negociate(unsigned to_srv, struct cursor *cursor, struct cifs_proto_info *info)
{
    // We are only interested in negociate response
    if (!to_srv) return PROTO_OK;


    return PROTO_OK;
}

static enum proto_parse_status cifs_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    /* Sanity checks */
    if (wire_len < CIFS_HEADER_SIZE) return PROTO_PARSE_ERR;
    if (cap_len < CIFS_HEADER_SIZE) return PROTO_TOO_SHORT;

    SLOG(LOG_DEBUG, "Parse of a cifs packet");
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

    enum proto_parse_status status = PROTO_OK;
    switch (info.command) {
        case SMB_COM_NEGOCIATE:
            status = parse_negociate(to_srv, &cursor, &info);
            break;
        default:
            break;
    }

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
        .parser_new = uniq_parser_new,
        .parser_del = uniq_parser_del,
        .info_2_str = cifs_info_2_str,
        .info_addr  = cifs_info_addr,
    };
    uniq_proto_ctor(&uniq_proto_cifs, &ops, "CIFS", PROTO_CODE_CIFS);
}

void cifs_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    uniq_proto_dtor(&uniq_proto_cifs);
#   endif
    log_category_proto_cifs_fini();
}
