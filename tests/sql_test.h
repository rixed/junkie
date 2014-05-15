// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <junkie/proto/sql.h>

int compare_expected_sql(struct sql_proto_info const *info, struct sql_proto_info const *expected);
void check_sql_set(struct sql_proto_info const *info, struct sql_proto_info const *expected, unsigned set);

