// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef POSTGRES_H_110105
#define POSTGRES_H_110105
#include <stdint.h>
#include <stdbool.h>
#include <junkie/proto/proto.h>

/** @file
 * @brief Postgres protocol informations
 */

extern struct proto *proto_postgres;

/// Description of a postgres message
struct postgres_proto_info {
    struct proto_info info;             ///< Generic infos
    bool is_query;                      ///< Set if the message is sent by the client
    enum pg_msg_type {                  ///< The phase where the connection is at
        PG_STARTUP,                     ///< Connection establishment
        PG_QUERY,                       ///< Query
        PG_EXIT,                        ///< Terminating the connection
    } msg_type;
    // Set values for PG_STARTUP
#   define PG_SSL_REQUEST 0x01
#   define PG_USER        0x02
#   define PG_DBNAME      0x04
#   define PG_PASSWD      0x08
#   define PG_CNX_DONE    0x10
    // Set values for PG_QUERY
#   define PG_SQL         0x01
#   define PG_STATUS      0x02
#   define PG_NB_ROWS     0x04
#   define PG_NB_FIELDS   0x08
    unsigned set_values;
    union {
        struct pg_startup {
            enum pg_ssl {               ///< Was SSL required ?
                PG_SSL_REQUESTED,
                PG_SSL_GRANTED,
                PG_SSL_REFUSED,
            } ssl_request;
            char user[64];
            char dbname[64];
            char passwd[64];
        } startup;
        struct pg_query {
            char sql[256];
            unsigned status;
            unsigned nb_rows;
            unsigned nb_fields;
        } query;
    } u;
};

void postgres_init(void);
void postgres_fini(void);

#endif
