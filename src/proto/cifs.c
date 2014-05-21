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

enum smb_file_info_levels {
    QUERY_FILE_UNIX_BASIC = 0x0200,
    QUERY_FILE_UNIX_LINK = 0x0201,
    QUERY_POSIX_ACL = 0x0204,
    QUERY_XATTR = 0x0205,
    QUERY_ATTR_FLAGS = 0x0206,
    QUERY_POSIX_PERMISSION = 0x0207,
    QUERY_POSIX_LOCK = 0x0208,
    SMB_POSIX_PATH_OPEN = 0x0209,
    SMB_POSIX_PATH_UNLINK = 0x020a,
    SMB_QUERY_FILE_UNIX_INFO2 = 0x020b,
};

static char const *smb_file_info_levels_2_str(enum smb_file_info_levels level)
{
    switch (level) {
    case QUERY_FILE_UNIX_BASIC     : return "QUERY_FILE_UNIX_BASIC";
    case QUERY_FILE_UNIX_LINK      : return "QUERY_FILE_UNIX_LINK";
    case QUERY_POSIX_ACL           : return "QUERY_POSIX_ACL";
    case QUERY_XATTR               : return "QUERY_XATTR";
    case QUERY_ATTR_FLAGS          : return "QUERY_ATTR_FLAGS";
    case QUERY_POSIX_PERMISSION    : return "QUERY_POSIX_PERMISSION";
    case QUERY_POSIX_LOCK          : return "QUERY_POSIX_LOCK";
    case SMB_POSIX_PATH_OPEN       : return "SMB_POSIX_PATH_OPEN";
    case SMB_POSIX_PATH_UNLINK     : return "SMB_POSIX_PATH_UNLINK";
    case SMB_QUERY_FILE_UNIX_INFO2  : return "SMB_QUERY_FILE_UNIX_INFO2";
    default                             : return tempstr_printf("Unknown level of interest %d", level);
    }
}

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
        case SMB_COM_TREE_CONNECT_ANDX      : return "SMB_COM_TREE_CONNECT_ANDX";
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

static char const *smb_trans2_subcmd_2_str(enum smb_trans2_subcommand command)
{
    switch (command) {
        case SMB_TRANS2_OPEN2                    : return "SMB_TRANS2_OPEN2";
        case SMB_TRANS2_FIND_FIRST2              : return "SMB_TRANS2_FIND_FIRST2";
        case SMB_TRANS2_FIND_NEXT2               : return "SMB_TRANS2_FIND_NEXT2";
        case SMB_TRANS2_QUERY_FS_INFO            : return "SMB_TRANS2_QUERY_FS_INFO";
        case SMB_TRANS2_SET_FS_INFORMATION       : return "SMB_TRANS2_SET_FS_INFORMATION";
        case SMB_TRANS2_QUERY_PATH_INFORMATION   : return "SMB_TRANS2_QUERY_PATH_INFORMATION";
        case SMB_TRANS2_SET_PATH_INFORMATION     : return "SMB_TRANS2_SET_PATH_INFORMATION";
        case SMB_TRANS2_QUERY_FILE_INFORMATION   : return "SMB_TRANS2_QUERY_FILE_INFORMATION";
        case SMB_TRANS2_SET_FILE_INFORMATION     : return "SMB_TRANS2_SET_FILE_INFORMATION";
        case SMB_TRANS2_FSCTL                    : return "SMB_TRANS2_FSCTL";
        case SMB_TRANS2_IOCTL2                   : return "SMB_TRANS2_IOCTL2";
        case SMB_TRANS2_FIND_NOTIFY_FIRST        : return "SMB_TRANS2_FIND_NOTIFY_FIRST";
        case SMB_TRANS2_FIND_NOTIFY_NEXT         : return "SMB_TRANS2_FIND_NOTIFY_NEXT";
        case SMB_TRANS2_CREATE_DIRECTORY         : return "SMB_TRANS2_CREATE_DIRECTORY";
        case SMB_TRANS2_SESSION_SETUP            : return "SMB_TRANS2_SESSION_SETUP";
        case SMB_TRANS2_GET_DFS_REFERRAL         : return "SMB_TRANS2_GET_DFS_REFERRAL";
        case SMB_TRANS2_REPORT_DFS_INCONSISTENCY : return "SMB_TRANS2_REPORT_DFS_INCONSISTENCY";
        default                                  : return tempstr_printf("Unknown smb command %d", command);
    }
}


static char const *smb_status_2_str(enum smb_status status)
{
    switch (status) {
        case SMB_STATUS_OK                             : return "SMB_STATUS_OK";
        case SMB_STATUS_ACCESS_DENIED                  : return "SMB_STATUS_ACCESS_DENIED";
        case SMB_STATUS_NETWORK_ACCESS_DENIED          : return "SMB_STATUS_NETWORK_ACCESS_DENIED";
        case SMB_STATUS_ACCOUNT_DISABLED               : return "SMB_STATUS_ACCOUNT_DISABLED";
        case SMB_STATUS_ACCOUNT_EXPIRED                : return "SMB_STATUS_ACCOUNT_EXPIRED";
        case SMB_STATUS_ALREADY_COMMITTED              : return "SMB_STATUS_ALREADY_COMMITTED";
        case SMB_STATUS_BAD_DEVICE_TYPE                : return "SMB_STATUS_BAD_DEVICE_TYPE";
        case SMB_STATUS_BAD_NETWORK_NAME               : return "SMB_STATUS_BAD_NETWORK_NAME";
        case SMB_STATUS_BUFFER_OVERFLOW                : return "SMB_STATUS_BUFFER_OVERFLOW";
        case SMB_STATUS_CANNOT_DELETE                  : return "SMB_STATUS_CANNOT_DELETE";
        case SMB_STATUS_CRC_ERROR                      : return "SMB_STATUS_CRC_ERROR";
        case SMB_STATUS_DATA_ERROR                     : return "SMB_STATUS_DATA_ERROR";
        case SMB_STATUS_DATA_ERROR_UNUSED              : return "SMB_STATUS_DATA_ERROR_UNUSED";
        case SMB_STATUS_DELETE_PENDING                 : return "SMB_STATUS_DELETE_PENDING";
        case SMB_STATUS_DEVICE_PAPER_EMPTY             : return "SMB_STATUS_DEVICE_PAPER_EMPTY";
        case SMB_STATUS_DFS_EXIT_PATH_FOUND            : return "SMB_STATUS_DFS_EXIT_PATH_FOUND";
        case SMB_STATUS_DIRECTORY_NOT_EMPTY            : return "SMB_STATUS_DIRECTORY_NOT_EMPTY";
        case SMB_STATUS_DISK_CORRUPT_ERROR             : return "SMB_STATUS_DISK_CORRUPT_ERROR";
        case SMB_STATUS_DISK_FULL                      : return "SMB_STATUS_DISK_FULL";
        case SMB_STATUS_EAS_NOT_SUPPORTED              : return "SMB_STATUS_EAS_NOT_SUPPORTED";
        case SMB_STATUS_EA_TOO_LARGE                   : return "SMB_STATUS_EA_TOO_LARGE";
        case SMB_STATUS_END_OF_FILE                    : return "SMB_STATUS_END_OF_FILE";
        case SMB_STATUS_FILE_CLOSED                    : return "SMB_STATUS_FILE_CLOSED";
        case SMB_STATUS_FILE_DELETED                   : return "SMB_STATUS_FILE_DELETED";
        case SMB_STATUS_FILE_IS_A_DIRECTORY            : return "SMB_STATUS_FILE_IS_A_DIRECTORY";
        case SMB_STATUS_FILE_LOCK_CONFLICT             : return "SMB_STATUS_FILE_LOCK_CONFLICT";
        case SMB_STATUS_FILE_RENAMED                   : return "SMB_STATUS_FILE_RENAMED";
        case SMB_STATUS_HANDLE_NOT_CLOSABLE            : return "SMB_STATUS_HANDLE_NOT_CLOSABLE";
        case SMB_STATUS_ILLEGAL_FUNCTION               : return "SMB_STATUS_ILLEGAL_FUNCTION";
        case SMB_STATUS_INSTANCE_NOT_AVAILABLE         : return "SMB_STATUS_INSTANCE_NOT_AVAILABLE";
        case SMB_STATUS_INSUFF_SERVER_RESOURCES        : return "SMB_STATUS_INSUFF_SERVER_RESOURCES";
        case SMB_STATUS_INVALID_DEVICE_REQUEST         : return "SMB_STATUS_INVALID_DEVICE_REQUEST";
        case SMB_STATUS_INVALID_DEVICE_STATE           : return "SMB_STATUS_INVALID_DEVICE_STATE";
        case SMB_STATUS_INVALID_HANDLE                 : return "SMB_STATUS_INVALID_HANDLE";
        case SMB_STATUS_INVALID_INFO_CLASS             : return "SMB_STATUS_INVALID_INFO_CLASS";
        case SMB_STATUS_INVALID_LOCK_SEQUENCE          : return "SMB_STATUS_INVALID_LOCK_SEQUENCE";
        case SMB_STATUS_INVALID_LOGON_HOURS            : return "SMB_STATUS_INVALID_LOGON_HOURS";
        case SMB_STATUS_INVALID_PARAMETER              : return "SMB_STATUS_INVALID_PARAMETER";
        case SMB_STATUS_INVALID_PIPE_STATE             : return "SMB_STATUS_INVALID_PIPE_STATE";
        case SMB_STATUS_INVALID_PORT_HANDLE            : return "SMB_STATUS_INVALID_PORT_HANDLE";
        case SMB_STATUS_INVALID_READ_MODE              : return "SMB_STATUS_INVALID_READ_MODE";
        case SMB_STATUS_INVALID_SMB                    : return "SMB_STATUS_INVALID_SMB";
        case SMB_STATUS_INVALID_VIEW_SIZE              : return "SMB_STATUS_INVALID_VIEW_SIZE";
        case SMB_STATUS_INVALID_WORKSTATION            : return "SMB_STATUS_INVALID_WORKSTATION";
        case SMB_STATUS_IO_TIMEOUT                     : return "SMB_STATUS_IO_TIMEOUT";
        case SMB_STATUS_LOCK_NOT_GRANTED               : return "SMB_STATUS_LOCK_NOT_GRANTED";
        case SMB_STATUS_LOGON_FAILURE                  : return "SMB_STATUS_LOGON_FAILURE";
        case SMB_STATUS_MEDIA_WRITE_PROTECTED          : return "SMB_STATUS_MEDIA_WRITE_PROTECTED";
        case SMB_STATUS_MORE_PROCESSING_REQUIRED       : return "SMB_STATUS_MORE_PROCESSING_REQUIRED";
        case SMB_STATUS_NETWORK_NAME_DELETED           : return "SMB_STATUS_NETWORK_NAME_DELETED";
        case SMB_STATUS_NO_MEDIA_IN_DEVICE             : return "SMB_STATUS_NO_MEDIA_IN_DEVICE";
        case SMB_STATUS_NO_MORE_FILES                  : return "SMB_STATUS_NO_MORE_FILES";
        case SMB_STATUS_NONEXISTENT_SECTOR             : return "SMB_STATUS_NONEXISTENT_SECTOR";
        case SMB_STATUS_NO_SPOOL_SPACE                 : return "SMB_STATUS_NO_SPOOL_SPACE";
        case SMB_STATUS_NO_SUCH_DEVICE                 : return "SMB_STATUS_NO_SUCH_DEVICE";
        case SMB_STATUS_NO_SUCH_FILE                   : return "SMB_STATUS_NO_SUCH_FILE";
        case SMB_STATUS_NOTIFY_ENUM_DIR                : return "SMB_STATUS_NOTIFY_ENUM_DIR";
        case SMB_STATUS_NOT_IMPLEMENTED                : return "SMB_STATUS_NOT_IMPLEMENTED";
        case SMB_STATUS_NOT_SAME_DEVICE                : return "SMB_STATUS_NOT_SAME_DEVICE";
        case SMB_STATUS_NOT_SUPPORTED                  : return "SMB_STATUS_NOT_SUPPORTED";
        case SMB_STATUS_OBJECT_NAME_COLLISION          : return "SMB_STATUS_OBJECT_NAME_COLLISION";
        case SMB_STATUS_OBJECT_NAME_NOT_FOUND          : return "SMB_STATUS_OBJECT_NAME_NOT_FOUND";
        case SMB_STATUS_OBJECT_PATH_INVALID            : return "SMB_STATUS_OBJECT_PATH_INVALID";
        case SMB_STATUS_OBJECT_PATH_NOT_FOUND          : return "SMB_STATUS_OBJECT_PATH_NOT_FOUND";
        case SMB_STATUS_OBJECT_PATH_SYNTAX_BAD         : return "SMB_STATUS_OBJECT_PATH_SYNTAX_BAD";
        case SMB_STATUS_OBJECT_TYPE_MISMATCH           : return "SMB_STATUS_OBJECT_TYPE_MISMATCH";
        case SMB_STATUS_OS2_ATOMIC_LOCKS_NOT_SUPPORTED : return "SMB_STATUS_OS2_ATOMIC_LOCKS_NOT_SUPPORTED";
        case SMB_STATUS_OS2_CANCEL_VIOLATION           : return "SMB_STATUS_OS2_CANCEL_VIOLATION";
        case SMB_STATUS_OS2_CANNOT_COPY                : return "SMB_STATUS_OS2_CANNOT_COPY";
        case SMB_STATUS_OS2_EA_ACCESS_DENIED           : return "SMB_STATUS_OS2_EA_ACCESS_DENIED";
        case SMB_STATUS_OS2_EAS_DIDNT_FIT              : return "SMB_STATUS_OS2_EAS_DIDNT_FIT";
        case SMB_STATUS_OS2_INVALID_ACCESS             : return "SMB_STATUS_OS2_INVALID_ACCESS";
        case SMB_STATUS_OS2_INVALID_LEVEL              : return "SMB_STATUS_OS2_INVALID_LEVEL";
        case SMB_STATUS_OS2_NEGATIVE_SEEK              : return "SMB_STATUS_OS2_NEGATIVE_SEEK";
        case SMB_STATUS_OS2_NO_MORE_SIDS               : return "SMB_STATUS_OS2_NO_MORE_SIDS";
        case SMB_STATUS_PASSWORD_EXPIRED               : return "SMB_STATUS_PASSWORD_EXPIRED";
        case SMB_STATUS_PASSWORD_MUST_CHANGE           : return "SMB_STATUS_PASSWORD_MUST_CHANGE";
        case SMB_STATUS_PATH_NOT_COVERED               : return "SMB_STATUS_PATH_NOT_COVERED";
        case SMB_STATUS_PIPE_BUSY                      : return "SMB_STATUS_PIPE_BUSY";
        case SMB_STATUS_PIPE_CLOSING                   : return "SMB_STATUS_PIPE_CLOSING";
        case SMB_STATUS_PIPE_DISCONNECTED              : return "SMB_STATUS_PIPE_DISCONNECTED";
        case SMB_STATUS_PIPE_EMPTY                     : return "SMB_STATUS_PIPE_EMPTY";
        case SMB_STATUS_PIPE_NOT_AVAILABLE             : return "SMB_STATUS_PIPE_NOT_AVAILABLE";
        case SMB_STATUS_PORT_CONNECTION_REFUSED        : return "SMB_STATUS_PORT_CONNECTION_REFUSED";
        case SMB_STATUS_PORT_DISCONNECTED              : return "SMB_STATUS_PORT_DISCONNECTED";
        case SMB_STATUS_PRINT_CANCELLED                : return "SMB_STATUS_PRINT_CANCELLED";
        case SMB_STATUS_PRINT_QUEUE_FULL               : return "SMB_STATUS_PRINT_QUEUE_FULL";
        case SMB_STATUS_PRIVILEGE_NOT_HELD             : return "SMB_STATUS_PRIVILEGE_NOT_HELD";
        case SMB_STATUS_PROCESS_IS_TERMINATING         : return "SMB_STATUS_PROCESS_IS_TERMINATING";
        case SMB_STATUS_RANGE_NOT_LOCKED               : return "SMB_STATUS_RANGE_NOT_LOCKED";
        case SMB_STATUS_REDIRECTOR_NOT_STARTED         : return "SMB_STATUS_REDIRECTOR_NOT_STARTED";
        case SMB_STATUS_REQUEST_NOT_ACCEPTED           : return "SMB_STATUS_REQUEST_NOT_ACCEPTED";
        case SMB_STATUS_SECTION_TOO_BIG                : return "SMB_STATUS_SECTION_TOO_BIG";
        case SMB_STATUS_SHARING_VIOLATION              : return "SMB_STATUS_SHARING_VIOLATION";
        case SMB_STATUS_SMB_BAD_COMMAND                : return "SMB_STATUS_SMB_BAD_COMMAND";
        case SMB_STATUS_SMB_BAD_FID                    : return "SMB_STATUS_SMB_BAD_FID";
        case SMB_STATUS_SMB_BAD_TID                    : return "SMB_STATUS_SMB_BAD_TID";
        case SMB_STATUS_SMB_BAD_UID                    : return "SMB_STATUS_SMB_BAD_UID";
        case SMB_STATUS_SMB_CONTINUE_MPX               : return "SMB_STATUS_SMB_CONTINUE_MPX";
        case SMB_STATUS_SMB_NO_SUPPORT                 : return "SMB_STATUS_SMB_NO_SUPPORT";
        case SMB_STATUS_SMB_USE_MPX                    : return "SMB_STATUS_SMB_USE_MPX";
        case SMB_STATUS_SMB_USE_STANDARD               : return "SMB_STATUS_SMB_USE_STANDARD";
        case SMB_STATUS_THREAD_IS_TERMINATING          : return "SMB_STATUS_THREAD_IS_TERMINATING";
        case SMB_STATUS_TOO_MANY_OPENED_FILES          : return "SMB_STATUS_TOO_MANY_OPENED_FILES";
        case SMB_STATUS_TOO_MANY_PAGING_FILES          : return "SMB_STATUS_TOO_MANY_PAGING_FILES";
        case SMB_STATUS_TOO_MANY_SESSIONS              : return "SMB_STATUS_TOO_MANY_SESSIONS";
        case SMB_STATUS_UNEXPECTED_NETWORK_ERROR       : return "SMB_STATUS_UNEXPECTED_NETWORK_ERROR";
        case SMB_STATUS_UNSUCCESSFUL                   : return "SMB_STATUS_UNSUCCESSFUL";
        case SMB_STATUS_WRONG_PASSWORD                 : return "SMB_STATUS_WRONG_PASSWORD";
        case SMB_STATUS_WRONG_VOLUME                   : return "SMB_STATUS_WRONG_VOLUME";
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
    size_t str_size = str_len + sizeof(marker);
    // we might stop in middle of the last character, fix it here
    if (str_size % 2) str_size++;
    size_t to_drop = str_size;
    SLOG(LOG_DEBUG, "Reading and converting %zu bytes", str_size);
    iconv(cd, (char **)&src, &str_size, &buf, &buf_size);
    cursor_drop(cursor, to_drop);
    return to_drop;
}

int cursor_drop_utf16(struct cursor *cursor, size_t max_len)
{
    SLOG(LOG_DEBUG, "Drop utf16 string");
    uint8_t marker[2] = {0x00, 0x00};
    int dropped_bytes = cursor_lookup_marker(cursor, marker, sizeof(marker), max_len);
    if (dropped_bytes < 0) return -1;
    dropped_bytes += sizeof(marker);
    if (dropped_bytes % 2) dropped_bytes++;
    cursor_drop(cursor, dropped_bytes);
    return dropped_bytes;
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
    uint16_t level_of_interest;
    uint16_t trans2_subcmd;
};

static int cifs_parser_ctor(struct cifs_parser *cifs_parser, struct proto *proto)
{
    SLOG(LOG_DEBUG, "Constructing cifs_parser@%p", cifs_parser);
    assert(proto == proto_cifs);
    if (0 != parser_ctor(&cifs_parser->parser, proto)) return -1;
    cifs_parser->unicode = true;
    cifs_parser->level_of_interest = 0;
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

// Parse helpers

static void const *cifs_info_addr(struct proto_info const *info_, size_t *size)
{
    struct cifs_proto_info const *info = DOWNCAST(info_, info, cifs_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *cifs_info_2_str(struct proto_info const *info_)
{
    struct cifs_proto_info const *info = DOWNCAST(info_, info, cifs_proto_info);
    char *str = tempstr_printf("%s, command=%s, status=%s",
            proto_info_2_str(info_),
            smb_command_2_str(info->command),
            smb_status_2_str(info->status));
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
    info->query_read_bytes = 0;
    info->query_write_bytes = 0;
    info->response_read_bytes = 0;
    info->response_write_bytes = 0;
    info->meta_read_bytes = 0;
    info->meta_write_bytes = 0;
    info->flag_file = 0;
}

int drop_smb_string(struct cifs_parser *cifs_parser, struct cursor *cursor)
{
    if (cifs_parser->unicode)
        return cursor_drop_utf16(cursor, cursor->cap_len);
    else
        return cursor_drop_string(cursor, cursor->cap_len);
}

#define DROP_SMB_STRING() if (drop_smb_string(cifs_parser, cursor) < 0) return PROTO_PARSE_ERR;

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

static uint8_t parse_and_check_word_count(struct cursor *cursor, uint8_t expected_word_count)
{
    if (expected_word_count == 0xff) return 0;
    uint8_t total_expected = expected_word_count + 1;
    if (cursor->cap_len < total_expected) return 0;
    uint8_t word_count = cursor_read_u8(cursor);
    if (expected_word_count != word_count) {
        SLOG(LOG_DEBUG, "Expected word count of 0x%02"PRIx8", got 0x%02"PRIx8, expected_word_count, word_count);
        return 0;
    }
    return word_count;
}

static uint8_t parse_and_check_word_count_superior(struct cursor *cursor, uint8_t minimum_word_count)
{
    if (minimum_word_count == 0xff) return 0;
    uint8_t total_minimum = minimum_word_count + 1;
    if (cursor->cap_len < total_minimum) return 0;
    uint8_t word_count = cursor_read_u8(cursor);
    if (word_count < minimum_word_count) {
        SLOG(LOG_DEBUG, "Expected word count should be >= 0x%02"PRIx8", got 0x%02"PRIx8, minimum_word_count, word_count);
        return 0;
    }
    return word_count;
}

static uint16_t parse_and_check_byte_count(struct cursor *cursor, uint8_t minimum_byte_count)
{
    if (cursor->cap_len < 2) return 0;
    uint16_t byte_count = cursor_read_u16le(cursor);
    SLOG(LOG_DEBUG, "Byte count is 0x%"PRIx16, byte_count);
    if (byte_count < minimum_byte_count) {
        SLOG(LOG_DEBUG, "Byte count is too small  (%02"PRIx8" > %02"PRIx16, minimum_byte_count, byte_count);
        return 0;
    }
    if (cursor->cap_len < byte_count) return 0;
    return byte_count;
}

static void parse_fid(struct cursor *cursor, struct cifs_proto_info *info)
{
    info->fid = cursor_read_u16le(cursor);
    SLOG(LOG_DEBUG, "Found fid 0x%"PRIx16, info->fid);
    info->set_values |= SMB_FID;
}

// Parse functions

/*
 * Negociate response:
 * Word count: 0x11
 *
 * Parameters
 * | USHORT        | UCHAR         | USHORT      | USHORT       | ULONG         | ULONG      | ULONG      | ULONG        | 8 bytes    | USHORT         | UCHAR           |
 * | Dialect Index | Security mode | MaxMpxCount | MaxNumberVcs | MaxBufferSize | MaxRawSize | SessionKey | Capabilities | SystemTime | ServerTimeZone | ChallengeLength |
 *
 * Data
 * | <Challenge length> bytes | smb string |
 * | Challenge                | domain     |
 */
static enum proto_parse_status parse_negociate(struct cifs_parser *cifs_parser, unsigned to_srv,
        struct cursor *cursor, struct cifs_proto_info *info)
{
    SLOG(LOG_DEBUG, "Parse of negociate to_srv: %d", to_srv);
    // We are only interested in negociate response
    if (!to_srv) return PROTO_OK;
    if (parse_and_check_word_count(cursor, 0x11) == 0)
        return PROTO_PARSE_ERR;
    // Reach capabilities
    cursor_drop(cursor, 19);
    parse_capabilities(cifs_parser, cursor);

    cursor_drop(cursor, 10);
    uint8_t challenge_length = cursor_read_u8(cursor);
    if (parse_and_check_byte_count(cursor, challenge_length) == 0) return PROTO_PARSE_ERR;
    cursor_drop(cursor, challenge_length);

    if (parse_smb_string(cifs_parser, cursor, info->domain, sizeof(info->domain)) < 0)
        return PROTO_PARSE_ERR;
    info->set_values |= SMB_DOMAIN;
    SLOG(LOG_DEBUG, "Found domain %s", info->domain);

    return PROTO_OK;
}

static uint8_t compute_padding(struct cursor *cursor, uint8_t offset, size_t alignment)
{
    return (cursor->cap_len - offset) % alignment;
}

/*
 * Session setup query
 * Word count: 0x0d
 *
 * Parameters
 * | 4 bytes | USHORT        | USHORT      | USHORT   | ULONG      | USHORT         | USHORT             | ULONG    | ULONG        |
 * | Andx    | MaxBufferSize | MaxMpxCount | VcNumber | SessionKey | OEMPasswordLen | UnicodePasswordLen | Reserved | Capabilities |
 *
 * Data
 * | UCHAR         | UCHAR             | UCHAR | SMB_STRING    | SMB_STRING      | SMB_STRING | SMB_STRING     |
 * | OEMPassword[] | UnicodePassword[] | Pad[] | AccountName[] | PrimaryDomain[] | NativeOS[] | NativeLanMan[] |
 */
static enum proto_parse_status parse_session_setup_query(struct cifs_parser *cifs_parser,
        struct cursor *cursor, struct cifs_proto_info *info)
{
    SLOG(LOG_DEBUG, "Parse of setup query");
    if (parse_and_check_word_count(cursor, 0x0d) == 0)
        return PROTO_PARSE_ERR;
    cursor_drop(cursor, 14);
    uint16_t oem_password_len = cursor_read_u16le(cursor);
    uint16_t unicode_password_len = cursor_read_u16le(cursor);
    cursor_drop(cursor, 4);
    parse_capabilities(cifs_parser, cursor);

    uint8_t padding = compute_padding(cursor, oem_password_len + unicode_password_len, 2);
    if (parse_and_check_byte_count(cursor, oem_password_len + unicode_password_len + padding) == 0) return PROTO_PARSE_ERR;
    cursor_drop(cursor, oem_password_len + unicode_password_len + padding);
    if (parse_smb_string(cifs_parser, cursor, info->user, sizeof(info->user)) < 0)
        return PROTO_PARSE_ERR;
    info->set_values |= SMB_USER;
    SLOG(LOG_DEBUG, "Found user %s", info->user);

    return PROTO_OK;
}

/*
 * Session setup response
 *
 * Word count: 0x03
 *
 * Parameters
 * | 4 bytes | USHORT |
 * | Andx    | Action |
 *
 * Data
 * | UCHAR | SMB_STRING | SMB_STRING     | SMB_STRING      |
 * | Pad[] | NativeOS[] | NativeLanMan[] | PrimaryDomain[] |
 */
static enum proto_parse_status parse_session_setup_response(struct cifs_parser *cifs_parser,
        struct cursor *cursor, struct cifs_proto_info *info)
{
    SLOG(LOG_DEBUG, "Parse of setup response");
    if (parse_and_check_word_count(cursor, 0x03) == 0) return PROTO_PARSE_ERR;
    cursor_drop(cursor, 0x03 * 2);

    if (parse_and_check_byte_count(cursor, 0) == 0) return PROTO_PARSE_ERR;
    uint8_t padding = compute_padding(cursor, 0, 2);
    CHECK_AND_DROP(padding);
    DROP_SMB_STRING(); // native os
    DROP_SMB_STRING(); // native lan man
    if (parse_smb_string(cifs_parser, cursor, info->domain, sizeof(info->domain)) < 0)
        return PROTO_PARSE_ERR;
    info->set_values |= SMB_DOMAIN;
    SLOG(LOG_DEBUG, "Found domain %s", info->domain);
    return PROTO_OK;
}

/*
 * Tree connect query
 * Word count: 0x04
 *
 * Parameters
 * | 4 bytes | USHORT | USHORT         |
 * | Andx    | Flags  | PasswordLength |
 *
 * Data
 * | UCHAR                    | UCHAR | SMB_STRING | OEM_STRING |
 * | Password[PasswordLength] | Pad[] | Path       | Service    |
 */
static enum proto_parse_status parse_tree_connect_and_request_query(struct cifs_parser *cifs_parser,
        struct cursor *cursor, struct cifs_proto_info *info)
{
    SLOG(LOG_DEBUG, "Parse Tree connect and request query");
    if (parse_and_check_word_count(cursor, 0x04) == 0) return PROTO_PARSE_ERR;
    cursor_drop(cursor, 6);
    uint16_t password_len = cursor_read_u16le(cursor);

    uint8_t padding = compute_padding(cursor, password_len, 2);
    if (parse_and_check_byte_count(cursor, password_len + padding) == 0) return PROTO_PARSE_ERR;
    cursor_drop(cursor, password_len + padding);
    if (parse_smb_string(cifs_parser, cursor, info->path, sizeof(info->path)) < 0)
        return PROTO_PARSE_ERR;
    info->set_values |= SMB_PATH;
    return PROTO_OK;
}

/*
 * Trans2 request
 * Word count > 0x0e
 *
 * Parameters
 * | USHORT              | USHORT         | USHORT            | USHORT       | UCHAR         | UCHAR     | USHORT | ULONG   | USHORT    |
 * | TotalParameterCount | TotalDataCount | MaxParameterCount | MaxDataCount | MaxSetupCount | Reserved1 | Flags  | Timeout | Reserved2 |
 *
 * | USHORT         | USHORT          | USHORT    | USHORT     | UCHAR      | UCHAR    | USHORT            |
 * | ParameterCount | ParameterOffset | DataCount | DataOffset | SetupCount | Reserved | Setup[SetupCount] |
 *
 * Data
 * | SMB_STRING | UCHAR  | UCHAR                             | UCHAR  | UCHAR                  |
 * | Name       | Pad1[] | Trans2_Parameters[ParameterCount] | Pad2[] | Trans2_Data[DataCount] |
 */
static enum proto_parse_status parse_trans2_request(struct cifs_parser *cifs_parser,
        struct cursor *cursor, struct cifs_proto_info *info)
{
    SLOG(LOG_DEBUG, "Parse trans2 request");
    cifs_parser->level_of_interest = 0;
    cifs_parser->trans2_subcmd = 0;
    uint8_t word_count = parse_and_check_word_count_superior(cursor, 0x0e);
    if (word_count == 0) return PROTO_PARSE_ERR;

    cursor_drop(cursor, 2 + 2 + 2 + 2 + 1); // total counts + max counts
    cursor_drop(cursor, 1 + 2 + 4 + 2); // Reserved + flags + timeout + reserved

    cursor_drop(cursor, 2); // parameter count
    uint16_t parameter_offset = cursor_read_u16le(cursor);
    cursor_drop(cursor, 2 + 2 + 1 + 1); // data count + data offset + setup count + reserved

    // TODO handle multiple setup count
    cifs_parser->trans2_subcmd = info->trans2_subcmd = cursor_read_u16le(cursor);
    info->set_values |= SMB_TRANS2_SUBCMD;

    uint8_t start_parameter = CIFS_HEADER_SIZE + word_count * 2 + 2 + 1;
    if (start_parameter > parameter_offset) {
        SLOG(LOG_DEBUG, "Start_parameter is greated than parameter offset (%"PRIu8" > %"PRIu8")", start_parameter, parameter_offset);
        return PROTO_PARSE_ERR;
    }
    uint8_t padding = parameter_offset - start_parameter;
    SLOG(LOG_DEBUG, "Found start parameter %u, offset %u, padding %u", start_parameter, parameter_offset, padding);
    parse_and_check_byte_count(cursor, padding);
    cursor_drop(cursor, padding);

    switch (info->trans2_subcmd) {
        case SMB_TRANS2_QUERY_PATH_INFORMATION:
            {
                CHECK(2 + 4);
                cursor_drop(cursor, 2 + 4);
                if (parse_smb_string(cifs_parser, cursor, info->path, sizeof(info->path)) < 0)
                    return PROTO_PARSE_ERR;
                info->set_values |= SMB_PATH;
            }
            break;
        case SMB_TRANS2_FIND_FIRST2:
            {
                CHECK(2 + 2 + 2 + 2 + 4 + 2);
                cursor_drop(cursor, 2 + 2 + 2 + 2 + 4);
                if (parse_smb_string(cifs_parser, cursor, info->path, sizeof(info->path)) < 0)
                    return PROTO_PARSE_ERR;
                info->set_values |= SMB_PATH;
            }
            break;
        case SMB_TRANS2_SET_PATH_INFORMATION:
            {
                CHECK(8);
                cifs_parser->level_of_interest = cursor_read_u16le(cursor);
                cursor_drop(cursor, 4); // Reserved
                if (parse_smb_string(cifs_parser, cursor, info->path, sizeof(info->path)) < 0)
                    return PROTO_PARSE_ERR;
                info->set_values |= SMB_PATH;

                switch(cifs_parser->level_of_interest) {
                    case SMB_POSIX_PATH_OPEN:
                        cursor_drop(cursor, 4); // drop flag fields
                        uint32_t posix_flags =cursor_read_u32le(cursor);
#define SMB_O_CREAT 0x10
#define SMB_O_DIRECTORY 0x200
                        if(SMB_O_CREAT == (posix_flags & SMB_O_CREAT))
                            info->flag_file |= SMB_FILE_CREATE;
                        if(SMB_O_DIRECTORY == (posix_flags & SMB_O_DIRECTORY))
                            info->flag_file |= SMB_FILE_DIRECTORY;
                        break;
                    case SMB_POSIX_PATH_UNLINK:
                        info->flag_file |= SMB_FILE_UNLINK;
                        break;
                    default:
                        break;
                }
            }
            break;
        case SMB_TRANS2_SET_FILE_INFORMATION:
            {
                CHECK(14);
                parse_fid(cursor, info);
            }
            break;
        default:
            break;
    }

    return PROTO_OK;
}

/*
 * Trans2 response
 *
 * Parameters
 *
 * | USHORT              | USHORT         | USHORT    | USHORT         | USHORT          | USHORT                | USHORT    | USHORT     | USHORT           | UCHAR      | UCHAR     | USHORT            |
 * | TotalParameterCount | TotalDataCount | Reserved1 | ParameterCount | ParameterOffset | ParameterDisplacement | DataCount | DataOffset | DataDisplacement | SetupCount | Reserved2 | Setup[SetupCount] |
 *
 * Data
 *
 * | UCHAR  | UCHAR                             | UCHAR  | UCHAR                  |
 * | Pad1[] | Trans2_Parameters[ParameterCount] | Pad2[] | Trans2_Data[DataCount] |
 *
 */
static enum proto_parse_status parse_trans2_response(struct cifs_parser *cifs_parser,
        struct cursor *cursor, struct cifs_proto_info *info)
{
    SLOG(LOG_DEBUG, "Parse trans2 response with previous subcmd %s",
            smb_trans2_subcmd_2_str(cifs_parser->trans2_subcmd));
    uint8_t word_count = parse_and_check_word_count_superior(cursor, 0x0a);
    if (word_count == 0) return PROTO_PARSE_ERR;

    cursor_drop(cursor, 2 + 2 + 2 + 2); // total counts + Reserved bytes + parameter count

    uint16_t parameter_offset = cursor_read_u16le(cursor);
    cursor_drop(cursor, 2 + 2); // parameter displacement + data count
    uint16_t data_offset = cursor_read_u16le(cursor);
    cursor_drop(cursor, 2 + 1); // data displacement + setup count
    cursor_drop(cursor, 1); // Reserved byte

    uint8_t start_parameter = CIFS_HEADER_SIZE + word_count * 2 + 2 + 1;
    uint8_t padding = parameter_offset - start_parameter;
    parse_and_check_byte_count(cursor, padding);
    cursor_drop(cursor, padding);

    enum proto_parse_status status = PROTO_OK;
    uint8_t data_padding = data_offset - parameter_offset;
    SLOG(LOG_DEBUG, "Parse trans2 specific subcmd with data padding %"PRIu8", level of interest %s",
            data_padding, smb_file_info_levels_2_str(cifs_parser->level_of_interest));
    switch (info->trans2_subcmd) {
        /*
         * Level of interest SMB_POSIX_PATH_OPEN
         * | USHORT | USHORD | ULONG        | USHORD                  | USHORT  | Sizeof reply information |
         * | Flags  | FID    | CreateAction | Reply information level | Padding | Reply information        |
         */
        case SMB_TRANS2_SET_PATH_INFORMATION:
            {
                // Parameters
                CHECK(2);
                cursor_drop(cursor, 2); // ea error offset
                cursor_drop(cursor, data_padding - 2);
                switch (cifs_parser->level_of_interest) {
                    case SMB_POSIX_PATH_OPEN:
                        {
                            CHECK(4);
                            // Data
                            cursor_drop(cursor, 2); // Flags
                            parse_fid(cursor, info);
                        }
                        break;
                    default:
                        break;
                }
            }
            break;

        case SMB_TRANS2_SET_FILE_INFORMATION:
            {
                CHECK(2);
                cursor_drop(cursor, 2); // ea error offset
                cursor_drop(cursor, data_padding - 2);
                // TODO Check error...
            }
            break;
        default:
            break;
    }
    return status;
}

/*
 * Write andx query
 * Word count 0x0c or 0x0e
 *
 * Parameters
 * | 4 bytes | USHORT | ULONG  | ULONG   |
 * | AndX    | FID    | Offset | Timeout |
 *
 * | USHORT    | USHORT    | USHORT   | USHORT     | USHORT     | ULONG                 |
 * | WriteMode | Remaining | Reserved | DataLength | DataOffset | OffsetHigh (optional) |
 *
 * Data
 * | UCHAR | UCHAR            |
 * | Pad   | Data[DataLength] |
 */
static enum proto_parse_status parse_write_andx_request(struct cursor *cursor, struct cifs_proto_info *info)
{
    if(0 == parse_and_check_word_count_superior(cursor, 0x0c))
        return PROTO_PARSE_ERR;
    cursor_drop(cursor, 4); // skip AndX
    parse_fid(cursor, info);
    cursor_drop(cursor, 4+4+2+2+2); // skip offset, timeout, writemode, remaining, reserved
    info->query_write_bytes = cursor_read_u16le(cursor);
    return PROTO_OK;
}

/*
 * Write andx response
 * Word count 0x06
 *
 * Parameters
 * | 4 bytes | USHORT | USHORT    | ULONG    |
 * | AndX    | Count  | Available | Reserved |
 *
 * No Data
 */
static enum proto_parse_status parse_write_andx_response(struct cursor *cursor, struct cifs_proto_info *info)
{
    if(0 == parse_and_check_word_count(cursor, 0x06))
        return PROTO_PARSE_ERR;
    cursor_drop(cursor, 4); // skip AndX
    info->response_write_bytes = cursor_read_u16le(cursor);
    return PROTO_OK;
}

/*
 * Close request
 * Word count 0x03
 *
 * Parameters
 * | USHORT | UTIME            |
 * | Count  | LastTimeModified |
 *
 * No Data
 */
static enum proto_parse_status parse_close_request(struct cursor *cursor, struct cifs_proto_info *info)
{
    if(0 == parse_and_check_word_count(cursor, 0x03))
        return PROTO_PARSE_ERR;
    parse_fid(cursor, info);
    return PROTO_OK;
}

/*
 * Read AndX request
 * Word count 0x0a or 0x0c
 *
 * Parameters
 * | 4 bytes | USHORT | ULONG  | ULONG   |
 * | AndX    | FID    | Offset | Timeout |
 *
 * | USHORT                  | USHORT                  | ULONG   | USHORT    | ULONG                 |
 * | MaxCountOfBytesToReturn | MinCountOfBytesToReturn | Timeout | Remaining | OffsetHigh (optional) |
 *
 * No Data
 */
static enum proto_parse_status parse_read_andx_request(struct cursor *cursor, struct cifs_proto_info *info)
{
    if(0 == parse_and_check_word_count_superior(cursor, 0x0a))
        return PROTO_PARSE_ERR;
    cursor_drop(cursor, 4); // skip AndX
    parse_fid(cursor, info);
    return PROTO_OK;
}

/*
 * Read AndX response
 * Word count 0x0c
 *
 * Parameters
 * | 4 bytes | USHORT    | USHORT             | USHORT    | USHORT     | USHORT     | USHORT * 5   |
 * | AndX    | Available | DataCompactionMode | Reserved1 | DataLength | DataOffset | Reserved2[5] |
 *
 * Data
 * | UCHAR | UCHAR |
 * | Pad[] | Data  |
 */
static enum proto_parse_status parse_read_andx_response(struct cursor *cursor, struct cifs_proto_info *info)
{
    if(0 == parse_and_check_word_count(cursor, 0x0c))
        return PROTO_PARSE_ERR;
    cursor_drop(cursor, 4+2+2+2); // skip AndX, Available, DataCompressionMode, Reserved
    info->response_read_bytes = cursor_read_u16le(cursor);
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

    SLOG(LOG_DEBUG, "Parse of a cifs command %s (0x%02x)", smb_command_2_str(info.command), info.command);
    enum proto_parse_status status = PROTO_OK;
    if (info.status == SMB_STATUS_OK) {
        switch (info.command) {
            case SMB_COM_SESSION_SETUP_ANDX:
                if (to_srv) status = parse_session_setup_response(cifs_parser, &cursor, &info);
                else status = parse_session_setup_query(cifs_parser, &cursor, &info);
                break;
            case SMB_COM_TREE_CONNECT_ANDX:
                status = parse_tree_connect_and_request_query(cifs_parser, &cursor, &info);
                break;
            case SMB_COM_NEGOCIATE:
                status = parse_negociate(cifs_parser, to_srv, &cursor, &info);
                break;
            case SMB_COM_TRANSACTION2:
                if (to_srv) status = parse_trans2_response(cifs_parser, &cursor, &info);
                else status = parse_trans2_request(cifs_parser, &cursor, &info);
                break;
            case SMB_COM_WRITE_ANDX:
                if (to_srv) status = parse_write_andx_response(&cursor, &info);
                else status = parse_write_andx_request(&cursor, &info);
                break;
            case SMB_COM_CLOSE:
                if (!to_srv) status = parse_close_request(&cursor, &info);
                break;
            case SMB_COM_READ_ANDX:
                if (to_srv) status = parse_read_andx_response(&cursor, &info);
                else status = parse_read_andx_request(&cursor, &info);
                break;
            default:
                break;
        }
    }
    if (status != PROTO_OK) {
        SLOG(LOG_DEBUG, "Probleme when parsing cifs: %s", proto_parse_status_2_str(status));
        return status;
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

