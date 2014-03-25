// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2014, SecurActive.
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

#include "junkie/proto/sql.h"

/*
 * Proto infos
 */

static char const *sql_ssl_2_str(enum sql_ssl ssl)
{
    switch (ssl) {
        case SQL_SSL_REQUESTED: return "SSL requested";
        case SQL_SSL_GRANTED:   return "SSL granted";
        case SQL_SSL_REFUSED:   return "SSL refused";
    }
    assert(!"Unknown sql_ssl");
    return "INVALID";
}

char const *sql_msg_type_2_str(enum sql_msg_type type)
{
    switch (type) {
        case SQL_UNKNOWN: return "unknown";
        case SQL_STARTUP: return "startup";
        case SQL_QUERY:   return "query";
        case SQL_EXIT:    return "exit";
    }
    assert(!"Unknown sql_msg_type");
    return "INVALID";
}

char const *sql_request_status_2_str(enum sql_request_status status)
{
    switch (status) {
        case SQL_REQUEST_COMPLETE: return "Completed";
        case SQL_REQUEST_INCOMPLETE: return "Not completed";
        case SQL_REQUEST_ERROR: return "Error";
    }
    assert(!"Unknown sql_request_status");
    return "INVALID";
}

char const *sql_encoding_2_str(enum sql_encoding encoding)
{
    switch (encoding) {
        case SQL_ENCODING_UTF8: return "UTF8";
        case SQL_ENCODING_LATIN1: return "Latin1";
        case SQL_ENCODING_LATIN9: return "Latin9";
        case SQL_ENCODING_UNKNOWN: return "Unknown";
        default:
            assert(!"Unknown sql_encoding");
            return "INVALID";
    }
}

static char const *startup_2_str(struct sql_proto_info const *info)
{
    return tempstr_printf(", %s%s%s%s%s%s%s%s%s",
        info->set_values & SQL_SSL_REQUEST ? sql_ssl_2_str(info->u.startup.ssl_request) : "No SSL",
        info->set_values & SQL_USER   ? ", user=" : "",
        info->set_values & SQL_USER   ? info->u.startup.user : "",
        info->set_values & SQL_DBNAME ? ", dbname=" : "",
        info->set_values & SQL_DBNAME ? info->u.startup.dbname : "",
        info->set_values & SQL_PASSWD ? ", passwd=" : "",
        info->set_values & SQL_PASSWD ? info->u.startup.passwd : "",
        info->set_values & SQL_ENCODING ? ", encoding=" : "",
        info->set_values & SQL_ENCODING ? sql_encoding_2_str(info->u.startup.encoding) : ""
        );
}

static char const *query_query_2_str(struct sql_proto_info const *info)
{
    return tempstr_printf("%s%s%s",
        info->set_values & SQL_SQL ? ", query='" : "",
        info->set_values & SQL_SQL ? info->u.query.sql : "",
        info->set_values & SQL_SQL ? "'" : "");
}

static char const *query_reply_2_str(struct sql_proto_info const *info)
{
    return tempstr_printf(", nb_rows=%d, nb_fields=%d",
        info->set_values & SQL_NB_ROWS   ? (int)info->u.query.nb_rows : -1,
        info->set_values & SQL_NB_FIELDS ? (int)info->u.query.nb_fields : -1);
}

static char const *exit_2_str(struct sql_proto_info const unused_ *info)
{
    return "";
}

static char const *version_info_2_str(struct sql_proto_info const *info)
{
    if (! (info->set_values & SQL_VERSION)) return "";
    return tempstr_printf(", version=%u.%u", info->version_maj, info->version_min);
}

char const *sql_info_2_str(struct proto_info const *info_)
{
    struct sql_proto_info const *info = DOWNCAST(info_, info, sql_proto_info);
    char *str = tempstr();

    char const *(*spec_info_2_str)(struct sql_proto_info const *) = NULL;
    switch (info->msg_type) {
        case SQL_UNKNOWN:
            break;
        case SQL_STARTUP:
            spec_info_2_str = startup_2_str;
            break;
        case SQL_QUERY:
            spec_info_2_str = info->is_query ? query_query_2_str : query_reply_2_str;
            break;
        case SQL_EXIT:
            spec_info_2_str = exit_2_str;
            break;
    }

    snprintf(str, TEMPSTR_SIZE, "%s, %s%s, %s%s%s%s%s%s%s%s%s%s",
        proto_info_2_str(info_),
        info->is_query ? "Clt->Srv" : "Srv->Clt",
        version_info_2_str(info),
        sql_msg_type_2_str(info->msg_type),
        spec_info_2_str ? spec_info_2_str(info) : "",
        info->set_values & SQL_REQUEST_STATUS ? ", Status=" : "",
        info->set_values & SQL_REQUEST_STATUS ? sql_request_status_2_str(info->request_status) : "",
        info->set_values & SQL_ERROR_SQL_STATUS ? ", SqlCode=" : "",
        info->set_values & SQL_ERROR_SQL_STATUS ? info->error_sql_status : "",
        info->set_values & SQL_ERROR_CODE ? ", ErrorCode=" : "",
        info->set_values & SQL_ERROR_CODE ? info->error_code : "",
        info->set_values & SQL_ERROR_MESSAGE ? ", ErrorMessage=" : "",
        info->set_values & SQL_ERROR_MESSAGE ? info->error_message : "");
    return str;
}

void const *sql_info_addr(struct proto_info const *info_, size_t *size)
{
    struct sql_proto_info const *info = DOWNCAST(info_, info, sql_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

// Set both the query and the flag that indicate if the query was truncated.
int sql_set_query(struct sql_proto_info *info, char const *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int size = vsnprintf(info->u.query.sql, sizeof(info->u.query.sql), fmt, args);
    va_end(args);
    if (size >= 0) {
        info->set_values |= SQL_SQL;
        info->u.query.truncated = ((unsigned)size >= sizeof(info->u.query.sql));
    }
    return size;
}

