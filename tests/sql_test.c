// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <junkie/proto/sql.h>
#include "sql_test.h"
#include "lib.h"

int compare_expected_sql(struct sql_proto_info const *info, struct sql_proto_info const *expected)
{
    CHECK_INT(info->info.head_len, expected->info.head_len);
    CHECK_INT(info->info.payload, expected->info.payload);

    if (info->msg_type != expected->msg_type) {
        printf("Expected msg_type %s, got %s\n", sql_msg_type_2_str(expected->msg_type),
                sql_msg_type_2_str(info->msg_type));
        return -1;
    }

    CHECK_SET_VALUE(info, expected, SQL_VERSION);
    CHECK_SET_VALUE(info, expected, SQL_REQUEST_STATUS);
    CHECK_SET_VALUE(info, expected, SQL_ERROR_CODE);
    CHECK_SET_VALUE(info, expected, SQL_ERROR_SQL_STATUS);
    CHECK_SET_VALUE(info, expected, SQL_ERROR_MESSAGE);
    CHECK_SET_VALUE(info, expected, SQL_SSL_REQUEST);
    CHECK_SET_VALUE(info, expected, SQL_USER);
    CHECK_SET_VALUE(info, expected, SQL_DBNAME);
    CHECK_SET_VALUE(info, expected, SQL_PASSWD);
    CHECK_SET_VALUE(info, expected, SQL_ENCODING);
    CHECK_SET_VALUE(info, expected, SQL_SQL);
    CHECK_SET_VALUE(info, expected, SQL_NB_ROWS);
    CHECK_SET_VALUE(info, expected, SQL_NB_FIELDS);

    CHECK_INT(expected->set_values, info->set_values);
    printf("%s\n", sql_info_2_str(&info->info));
    if (VALUES_ARE_SET(expected, SQL_VERSION)) {
        CHECK_INT(info->version_maj, expected->version_maj);
        CHECK_INT(info->version_min, expected->version_min);
    }
    if (VALUES_ARE_SET(expected, (SQL_NB_FIELDS)))
        CHECK_INT(info->u.query.nb_fields, expected->u.query.nb_fields);
    if (VALUES_ARE_SET(expected, SQL_REQUEST_STATUS))
        CHECK_INT(info->request_status, expected->request_status);
    if (VALUES_ARE_SET(expected, SQL_ERROR_CODE))
        CHECK_STR(info->error_code, expected->error_code);
    if (VALUES_ARE_SET(expected, SQL_ERROR_MESSAGE))
        CHECK_STR(info->error_message, expected->error_message);
    if (VALUES_ARE_SET(expected, SQL_NB_ROWS))
        CHECK_INT(info->u.query.nb_rows, expected->u.query.nb_rows);
    if (VALUES_ARE_SET(expected, SQL_SQL)) {
        CHECK_STR(info->u.query.sql, expected->u.query.sql);
        CHECK_INT(info->u.query.truncated, expected->u.query.truncated);
    }
    if (VALUES_ARE_SET(expected, SQL_ENCODING))
        CHECK_INT(info->u.startup.encoding, expected->u.startup.encoding);
    if (VALUES_ARE_SET(expected, SQL_USER))
        CHECK_STR(info->u.startup.user, expected->u.startup.user);
    if (VALUES_ARE_SET(expected, SQL_DBNAME))
        CHECK_STR(info->u.startup.dbname, expected->u.startup.dbname);
    if (VALUES_ARE_SET(expected, SQL_PASSWD))
        CHECK_STR(info->u.startup.passwd, expected->u.startup.passwd);
    return 0;
}

