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
extern struct proto *proto_tds;

#define pgsql_proto_info sql_proto_info
#define mysql_proto_info sql_proto_info
#define tns_proto_info sql_proto_info
#define tds_proto_info sql_proto_info

#define SQL_ERROR_SQL_STATUS_SIZE 5 // Size of generic sql error code

/// Description of a sql message
struct sql_proto_info {
    struct proto_info info;             ///< Generic infos
    bool is_query;                      ///< Set if the message is sent by the client
    enum sql_msg_type {                 ///< The phase where the connection is at
        SQL_UNKNOWN,                    ///< When we do not understand the protocol, but know that it actually is this protocol
        SQL_STARTUP,                    ///< Connection establishment
        SQL_QUERY,                      ///< Query
        SQL_EXIT,                       ///< Terminating the connection
    } msg_type;
#   define SQL_VERSION              0x0001
    // Set value for request_status
#   define SQL_REQUEST_STATUS       0x0002
#   define SQL_ERROR_CODE           0x0004
#   define SQL_ERROR_SQL_STATUS     0x0800
#   define SQL_ERROR_MESSAGE        0x1000
    // Set values for SQL_STARTUP
#   define SQL_SSL_REQUEST          0x0010
#   define SQL_USER                 0x0020
#   define SQL_DBNAME               0x0040
#   define SQL_PASSWD               0x0080
    // Set values for SQL_QUERY
#   define SQL_SQL                  0x0100
#   define SQL_NB_ROWS              0x0200
#   define SQL_NB_FIELDS            0x0400
    unsigned set_values;
    unsigned version_maj, version_min;  ///< Version of the protocol
    // True if this message is the last message of a query / command

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
        } startup;
        struct sql_query {
            char sql[512];
            unsigned nb_rows;
            unsigned nb_fields;
        } query;
    } u;
};

char const *sql_msg_type_2_str(enum sql_msg_type type);
char const *sql_info_2_str(struct proto_info const *);
void const *sql_info_addr(struct proto_info const *, size_t *);
void sql_serialize(struct proto_info const *, uint8_t **buf);
void sql_deserialize(struct proto_info *, uint8_t const **buf);

void pgsql_init(void);
void pgsql_fini(void);
void mysql_init(void);
void mysql_fini(void);
void tns_init(void);
void tns_fini(void);
void tds_init(void);
void tds_fini(void);

#endif
