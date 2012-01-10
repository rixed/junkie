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

#define pgsql_proto_info sql_proto_info
#define mysql_proto_info sql_proto_info
#define tns_proto_info sql_proto_info

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
#   define SQL_VERSION     0x01
    // Set values for SQL_STARTUP
#   define SQL_SSL_REQUEST 0x02
#   define SQL_USER        0x04
#   define SQL_DBNAME      0x08
#   define SQL_PASSWD      0x10
#   define SQL_AUTH_STATUS 0x20
    // Set values for SQL_QUERY
#   define SQL_SQL         0x02
#   define SQL_STATUS      0x04
#   define SQL_NB_ROWS     0x08
#   define SQL_NB_FIELDS   0x10
    unsigned set_values;
    unsigned version_maj, version_min;  ///< Version of the protocol
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
            unsigned status;
        } startup;
        struct sql_query {
            char sql[256];
            unsigned status;
            unsigned nb_rows;
            unsigned nb_fields;
        } query;
    } u;
};

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

#endif
