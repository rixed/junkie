// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef HTTP_H_100429
#define HTTP_H_100429
#include <stdbool.h>
#include <junkie/proto/proto.h>
#include <junkie/tools/ip_addr.h>

/** @file
 * @brief HTTP informations
 */

/// We use a dedicated log category (@see log.h) for everything related to this proto
LOG_CATEGORY_DEC(proto_http)

extern struct proto *proto_http;

/// HTTP message
struct http_proto_info {
    struct proto_info info;         ///< Header and payload sizes
#   define HTTP_METHOD_SET             0x1
#   define HTTP_CODE_SET               0x2
#   define HTTP_LENGTH_SET             0x4
#   define HTTP_MIME_SET               0x8
#   define HTTP_HOST_SET               0x10
#   define HTTP_URL_SET                0x20
#   define HTTP_TRANSFERT_ENCODING_SET 0x40
#   define HTTP_USER_AGENT_SET         0x80
#   define HTTP_REFERRER_SET           0x100
    uint32_t set_values;            ///< Mask of the fields that are actually set in this struct
    enum http_method {
        HTTP_METHOD_GET, HTTP_METHOD_HEAD, HTTP_METHOD_POST, HTTP_METHOD_CONNECT,
        HTTP_METHOD_PUT, HTTP_METHOD_OPTIONS, HTTP_METHOD_TRACE, HTTP_METHOD_DELETE,
    } method;                       ///< The method used
    unsigned code;                  ///< The response code, if the message is a response
    unsigned content_length;        ///< The Content-Length, if present
    bool chunked_encoding;          ///< Set if the transfert encoding is chunked (only relevant if set_values&HTTP_TRANSFERT_ENCODING_SET)
    unsigned mime_type;             ///< The Mime-type, if present (as offset in strs)
    unsigned host;                  ///< The Host, if present (as offset in strs)
    unsigned user_agent;            ///< The User-Agent field, if present (as offset in strs)
    unsigned referrer;              ///< The Referrer field, if present (as offset in strs)
    unsigned url;                   ///< The URL, for methods that have one (as offset in strs)
#   define HTTP_STRS_SIZE 4000      ///< So that the whole http_info is below 4k
#   define HTTP_MAX_URL_SIZE 3500   ///< Do not fill up strs with the URL only
    unsigned free_strs;             ///< Offset of the next free byte in strs
    char strs[HTTP_STRS_SIZE];      ///< We store all the previous strings in there, as nul term strings
};

#define HTTP_IS_QUERY(http) ((http)->set_values & HTTP_METHOD_SET)

/// @return the name of an HTTP method
char const *http_method_2_str(enum http_method);

/// Helper to build a host/url string from host, url and server ip.
/** @return a tempstr or a pointer to url, none of which ought to be freed. */
char const *http_build_url(struct ip_addr const *server, char const *host, char const *url);

/// Helper to build the domainname from the ip, host and/or url components.
/** @return a tempstr or host, with just the domainname without URL nor "http://" nor ports.
 * @note IP address are written in v6 format. */
char const *http_build_domain(struct ip_addr const *server, char const *host, char const *url, int version);

void http_init(void);
void http_fini(void);

#endif
