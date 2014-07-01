// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef SQL_H_110105
#define SQL_H_110105
#include <stdint.h>
#include <stdbool.h>
#include <junkie/proto/proto.h>

/** @file
 * @brief Database protocol informations
 */

extern struct proto *proto_pgsql;
extern struct proto *proto_mysql;
extern struct proto *proto_tns;
extern struct proto *proto_tds_msg;

#define pgsql_proto_info sql_proto_info
#define mysql_proto_info sql_proto_info
#define tns_proto_info sql_proto_info
#define tds_msg_proto_info sql_proto_info

#define SQL_ERROR_SQL_STATUS_SIZE 5 // Size of generic sql error code
#define SQL_QUERY_SIZE 4096

/// Description of a sql message
struct sql_proto_info {
    struct proto_info info;             ///< Generic infos
    bool is_query;                      ///< Set if the message is sent by the client
    enum sql_msg_type {                 ///< The phase where the connection is at
        SQL_UNKNOWN,                    ///< When we do not understand the protocol, but know that it actually is this protocol
        SQL_STARTUP,                    ///< Connection establishment
        SQL_QUERY,                      ///< Query (or response)
        SQL_EXIT,                       ///< Terminating the connection
    } msg_type;
#   define SQL_VERSION              0x0001
    // Set value for request_status
#   define SQL_REQUEST_STATUS       0x0002
#   define SQL_ERROR_CODE           0x0004
#   define SQL_ERROR_SQL_STATUS     0x0008
#   define SQL_ERROR_MESSAGE        0x0010
    // Set values for SQL_STARTUP
#   define SQL_SSL_REQUEST          0x0020
#   define SQL_USER                 0x0040
#   define SQL_DBNAME               0x0080
#   define SQL_PASSWD               0x0100
#   define SQL_ENCODING             0x0200
    // Set values for SQL_QUERY
#   define SQL_SQL                  0x0400
#   define SQL_NB_ROWS              0x0800
#   define SQL_NB_FIELDS            0x1000
    unsigned set_values;
    unsigned version_maj, version_min;  ///< Version of the protocol
    struct timeval first_ts;

    enum sql_request_status {
        SQL_REQUEST_INCOMPLETE,
        SQL_REQUEST_COMPLETE,
        SQL_REQUEST_ERROR,
    } request_status;

    char error_sql_status[6];  // Standard sql status
    char error_code[16];       // Protocol specific error code
    char error_message[256];   // Error message

    union {
        struct sql_startup {
            enum sql_ssl {              ///< Was SSL required ?
                SQL_SSL_REQUESTED,
                SQL_SSL_GRANTED,
                SQL_SSL_REFUSED,
            } ssl_request;
            char user[64];
            char dbname[64];
            char passwd[64];
            enum sql_encoding {
                SQL_ENCODING_UNKNOWN=0,
                SQL_ENCODING_UTF8,
                SQL_ENCODING_LATIN1,
                SQL_ENCODING_LATIN9,
                SQL_ENCODING_MAX
            } encoding;
        } startup;
        struct sql_query {
            char sql[SQL_QUERY_SIZE];    // UTF-8
            unsigned nb_rows;
            unsigned nb_fields;
            bool truncated;
        } query;
    } u;
};

char const *sql_encoding_2_str(enum sql_encoding encoding);
char const *sql_msg_type_2_str(enum sql_msg_type type);
char const *sql_info_2_str(struct proto_info const *);
char const *sql_request_status_2_str(enum sql_request_status status);
void const *sql_info_addr(struct proto_info const *, size_t *);
int sql_set_query(struct sql_proto_info *info, char const *fmt, ...);

void pgsql_init(void);
void pgsql_fini(void);
void mysql_init(void);
void mysql_fini(void);
void tns_init(void);
void tns_fini(void);
void tds_msg_init(void);
void tds_msg_fini(void);

static inline void sql_set_field_count(struct sql_proto_info *info, unsigned field_count)
{
    info->set_values |= SQL_NB_FIELDS;
    info->u.query.nb_fields = field_count;
}

static inline void sql_increment_field_count(struct sql_proto_info *info, unsigned count)
{
    if (info->set_values & SQL_NB_FIELDS) {
        info->u.query.nb_fields += count;
    } else {
        info->set_values |= SQL_NB_FIELDS;
        info->u.query.nb_fields = count;
    }
}

static inline void sql_set_row_count(struct sql_proto_info *info, unsigned count)
{
    info->set_values |= SQL_NB_ROWS;
    info->u.query.nb_rows = count;
}

static inline void sql_set_encoding(struct sql_proto_info *info, enum sql_encoding encoding)
{
    info->set_values |= SQL_ENCODING;
    info->u.startup.encoding = encoding;
}

static inline void sql_increment_row_count(struct sql_proto_info *info, unsigned count)
{
    if (info->set_values & SQL_NB_ROWS) {
        info->u.query.nb_rows += count;
    } else {
        info->set_values |= SQL_NB_ROWS;
        info->u.query.nb_rows = count;
    }
}

static inline void sql_set_request_status(struct sql_proto_info *info, enum sql_request_status status)
{
    info->set_values |= SQL_REQUEST_STATUS;
    info->request_status = status;
}

#endif
