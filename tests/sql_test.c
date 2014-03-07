// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <junkie/proto/sql.h>
#include "sql_test.h"

static char const *set_value_2_str(unsigned value)
{
    switch (value) {
        case SQL_VERSION:
            return "SQL_VERSION";
        case SQL_REQUEST_STATUS:
            return "SQL_REQUEST_STATUS";
        case SQL_ERROR_CODE:
            return "SQL_ERROR_CODE";
        case SQL_ERROR_SQL_STATUS:
            return "SQL_ERROR_SQL_STATUS";
        case SQL_ERROR_MESSAGE:
            return "SQL_ERROR_MESSAGE";
        case SQL_SSL_REQUEST:
            return "SQL_SSL_REQUEST";
        case SQL_USER:
            return "SQL_USER";
        case SQL_DBNAME:
            return "SQL_DBNAME";
        case SQL_PASSWD:
            return "SQL_PASSWD";
        case SQL_SQL:
            return "SQL_SQL";
        case SQL_NB_ROWS:
            return "SQL_NB_ROWS";
        case SQL_NB_FIELDS:
            return "SQL_NB_FIELDS";
        case SQL_ENCODING:
            return "SQL_ENCODING";
    }
    printf("Unknown value %d\n", value);
    return "Unknown";
}

void check_sql_set(struct sql_proto_info const *info, struct sql_proto_info const *expected, unsigned set)
{
    unsigned expected_set = expected->set_values & set;
    unsigned value_set = info->set_values & set;
    if (expected_set != value_set) {
        if (0 != expected_set) {
            printf("Expected %s to be set\n", set_value_2_str(set));
            assert(expected_set == value_set);
        } else {
            printf("Unexpected %s value\n", set_value_2_str(set));
            assert(expected_set != value_set);
        }
    }
}

int compare_expected_sql(struct sql_proto_info const *info, struct sql_proto_info const *expected)
{
    CHECK_INT(info->info.head_len, expected->info.head_len);
    CHECK_INT(info->info.payload, expected->info.payload);

    if (info->msg_type != expected->msg_type) {
        printf("Expected msg_type %s, got %s\n", sql_msg_type_2_str(expected->msg_type),
                sql_msg_type_2_str(info->msg_type));
        return -1;
    }

    check_sql_set(info, expected, SQL_VERSION);
    check_sql_set(info, expected, SQL_REQUEST_STATUS);
    check_sql_set(info, expected, SQL_ERROR_CODE);
    check_sql_set(info, expected, SQL_ERROR_SQL_STATUS);
    check_sql_set(info, expected, SQL_ERROR_MESSAGE);
    check_sql_set(info, expected, SQL_SSL_REQUEST);
    check_sql_set(info, expected, SQL_USER);
    check_sql_set(info, expected, SQL_DBNAME);
    check_sql_set(info, expected, SQL_PASSWD);
    check_sql_set(info, expected, SQL_ENCODING);
    check_sql_set(info, expected, SQL_SQL);
    check_sql_set(info, expected, SQL_NB_ROWS);
    check_sql_set(info, expected, SQL_NB_FIELDS);

    CHECK_INT(expected->set_values, info->set_values);
    printf("%s\n", sql_info_2_str(&info->info));
    if ((expected->set_values & SQL_VERSION) == SQL_VERSION) {
        CHECK_INT(info->version_maj, expected->version_maj);
        CHECK_INT(info->version_min, expected->version_min);
    }
    if ((expected->set_values & (SQL_NB_FIELDS)) == (SQL_NB_FIELDS))
        CHECK_INT(info->u.query.nb_fields, expected->u.query.nb_fields);
    if ((expected->set_values & (SQL_REQUEST_STATUS)) == (SQL_REQUEST_STATUS))
        CHECK_INT(info->request_status, expected->request_status);
    if ((expected->set_values & (SQL_ERROR_CODE)) == (SQL_ERROR_CODE))
        CHECK_STR(info->error_code, expected->error_code);
    if ((expected->set_values & (SQL_ERROR_MESSAGE)) == (SQL_ERROR_MESSAGE))
        CHECK_STR(info->error_message, expected->error_message);
    if ((expected->set_values & (SQL_NB_ROWS)) == (SQL_NB_ROWS))
        CHECK_INT(info->u.query.nb_rows, expected->u.query.nb_rows);
    if ((expected->set_values & (SQL_SQL)) == (SQL_SQL))
        CHECK_STR(info->u.query.sql, expected->u.query.sql);
    if ((expected->set_values & (SQL_ENCODING)) == (SQL_ENCODING))
        CHECK_INT(info->u.startup.encoding, expected->u.startup.encoding);
    return 0;
}

