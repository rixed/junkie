// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <junkie/proto/sql.h>

#define CHECK_INT(VAL, EXP) do {                  \
    unsigned exp = EXP;                           \
    unsigned val = VAL;                           \
    if (exp != val) {                             \
        printf("Expected %d got %d from field %s\n", exp, val, #VAL); \
        return 1;                                 \
    } } while (0)

#define CHECK_STR(VAL, EXP) do {               \
    char *exp = (char *)EXP;                              \
    char *val = (char *)VAL;                              \
    if (0 != strcmp(exp, val)) {                  \
        printf("Expected '%s' got '%s' from field %s\n", exp, val, #VAL); \
        return 1;                                 \
    } } while (0)

enum way { FROM_CLIENT, FROM_SERVER };
char const *set_value_2_str(unsigned value);
int compare_expected_sql(struct sql_proto_info const *info, struct sql_proto_info const *expected);
void check_sql_set(struct sql_proto_info const *info, struct sql_proto_info const *expected, unsigned set);

