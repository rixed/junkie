// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <string.h>
#include <inttypes.h>
#include <junkie/cpp.h>
#include <junkie/proto/cnxtrack.h>
#include <junkie/tools/hash.h>
#include <junkie/tools/mutex.h>
#include <junkie/tools/ext.h>
#include <junkie/tools/log.h>
#include "junkie/tools/objalloc.h"

#undef LOG_CAT
#define LOG_CAT cnxtrack_log_category

LOG_CATEGORY_DEF(cnxtrack);

static TAILQ_HEAD(cnxtrack_ips, cnxtrack_ip) cnxtrack_ips;   // all cnxtrack_ips ordered most recently used first
static HASH_TABLE(cnxtrack_ips_h, cnxtrack_ip) cnxtrack_ips_h;  // the hash of all defined cnxtrack_ips

static int64_t cnxtrack_timeout = 1000000; /* microseconds */
EXT_PARAM_RW(cnxtrack_timeout, "connection-tracking-timeout", int64, "After how many microseconds an unused tracked connection must be forgotten");

struct ip_addr cnxtrack_ip_addr_unknown;
struct mutex cnxtracker_lock;   // protects cnxtrack_ips list and hash

struct cnxtrack_ip {
    TAILQ_ENTRY(cnxtrack_ip) used_entry; // in the list of cnxtrack_ip ordered by last_used
    HASH_ENTRY(cnxtrack_ip) h_entry;    // in the hash list of collisions
    struct cnxtrack_ip_key {
        struct ip_key ip;
        struct port_key port;
    } packed_ key;
    struct proto *proto;
    struct proto *requestor;
    bool reuse;
    struct timeval last_used;
};

static int cnxtrack_ip_ctor(struct cnxtrack_ip *ct, unsigned ip_proto, struct ip_addr const *ip_a, uint16_t port_a, struct ip_addr const *ip_b, uint16_t port_b, bool reuse, struct proto *proto, struct timeval const *now, struct proto *requestor)
{
    SLOG(LOG_DEBUG, "Construct cnxtrack_ip@%p for proto %u, %s:%"PRIu16"->%s:%"PRIu16" for %s",
        ct, ip_proto, ip_addr_2_str(ip_a), port_a, ip_addr_2_str(ip_b), port_b, proto->name);

    ct->key.ip.protocol = ip_proto;
    ct->key.ip.addr[0] = *ip_a;
    ct->key.ip.addr[1] = *ip_b;
    ct->key.port.port[0] = port_a;
    ct->key.port.port[1] = port_b;
    ct->proto = proto;
    ct->requestor = requestor;
    ct->reuse = reuse;
    ct->last_used = *now;

    mutex_lock(&cnxtracker_lock);
    TAILQ_INSERT_HEAD(&cnxtrack_ips, ct, used_entry);
    HASH_INSERT(&cnxtrack_ips_h, ct, &ct->key, h_entry);
    mutex_unlock(&cnxtracker_lock);

    return 0;
}

struct cnxtrack_ip *cnxtrack_ip_new(unsigned ip_proto, struct ip_addr const *ip_a, uint16_t port_a, struct ip_addr const *ip_b, uint16_t port_b, bool reuse, struct proto *proto, struct timeval const *now, struct proto *requestor)
{
    struct cnxtrack_ip *ct = objalloc_nice(sizeof(*ct), "cnxtrack_ip");
    if (! ct) return NULL;
    if (0 != cnxtrack_ip_ctor(ct, ip_proto, ip_a, port_a, ip_b, port_b, reuse, proto, now, requestor)) {
        objfree(ct);
        return NULL;
    }
    return ct;
}

// Caller must own cnxtracker_lock
static void cnxtrack_ip_dtor(struct cnxtrack_ip *ct)
{
    SLOG(LOG_DEBUG, "Destruct cnxtrack_ip@%p", ct);

    HASH_REMOVE(&cnxtrack_ips_h, ct, h_entry);
    TAILQ_REMOVE(&cnxtrack_ips, ct, used_entry);
}

static void cnxtrack_ip_del_locked(struct cnxtrack_ip *ct)
{
    cnxtrack_ip_dtor(ct);
    objfree(ct);
}

void cnxtrack_ip_del(struct cnxtrack_ip *ct)
{
    mutex_lock(&cnxtracker_lock);
    cnxtrack_ip_del_locked(ct);
    mutex_unlock(&cnxtracker_lock);
}

/*
 * Lookup
 */

// Caller must own cnxtracker_lock
static void cnxtrack_ip_timeout(struct timeval const *now)
{
    struct cnxtrack_ip *ct;
    while (NULL != (ct = TAILQ_LAST(&cnxtrack_ips, cnxtrack_ips))) {
        if (timeval_sub(now, &ct->last_used) <= cnxtrack_timeout) break;
        SLOG(LOG_DEBUG, "Timeouting cnxtrack_ip@%p", ct);
        cnxtrack_ip_del_locked(ct);
    }
}

// caller must own cnxtracker_lock
static struct cnxtrack_ip *ll_lookup(unsigned ip_proto, struct ip_addr const *ip_a, uint16_t port_a, struct ip_addr const *ip_b, uint16_t port_b)
{
    struct cnxtrack_ip_key key = {
        .ip = {
            .protocol = ip_proto,
            .addr = { *ip_a, *ip_b },
        },
        .port = {
            .port = { port_a, port_b },
        },
    };
    struct cnxtrack_ip *ct;
    HASH_LOOKUP(ct, &cnxtrack_ips_h, &key, key, h_entry);
    return ct;
}

struct proto *cnxtrack_ip_lookup(unsigned ip_proto, struct ip_addr const *ip_a, uint16_t port_a, struct ip_addr const *ip_b, uint16_t port_b, struct timeval const *now, struct proto **requestor)
{
    struct proto *proto = NULL;

    SLOG(LOG_DEBUG, "Lookup tracked cnx for proto %u, %s:%"PRIu16"->%s:%"PRIu16,
        ip_proto, ip_addr_2_str(ip_a), port_a, ip_addr_2_str(ip_b), port_b);

    mutex_lock(&cnxtracker_lock);

    // Maybe rehash the hash?
    static time_t last_rehash = 0; // timestamp (seconds) of the last rehash
    if (now->tv_sec > last_rehash) {
        last_rehash = now->tv_sec;
        HASH_TRY_REHASH(&cnxtrack_ips_h, key, h_entry);
    }

    // Clean
    cnxtrack_ip_timeout(now);

    // Ok, look for an exact match first
    struct cnxtrack_ip *ct;
    ct = ll_lookup(ip_proto, ip_a, port_a, ip_b, port_b);
    if (ct) goto done;
    ct = ll_lookup(ip_proto, ip_b, port_b, ip_a, port_a);
    if (ct) goto done;

    // Maybe we lacked one IP address?
    ct = ll_lookup(ip_proto, ip_a, port_a, &cnxtrack_ip_addr_unknown, port_b);
    if (ct) goto done;
    ct = ll_lookup(ip_proto, ip_b, port_b, &cnxtrack_ip_addr_unknown, port_a);
    if (ct) goto done;

    // Maybe we lacked one port then?
    ct = ll_lookup(ip_proto, ip_a, port_a, ip_b, PORT_UNKNOWN);
    if (ct) goto done;
    ct = ll_lookup(ip_proto, ip_b, port_b, ip_a, PORT_UNKNOWN);
    if (ct) goto done;

    // It's becoming problematic. Maybe we had only one peer then?
    ct = ll_lookup(ip_proto, ip_a, port_a, &cnxtrack_ip_addr_unknown, PORT_UNKNOWN);
    if (ct) goto done;
    ct = ll_lookup(ip_proto, ip_b, port_b, &cnxtrack_ip_addr_unknown, PORT_UNKNOWN);
    if (ct) goto done;

    // I'm afraid we don't know this stream. so many hash searches for nothing...

done:
    if (ct) {
        proto = ct->proto;
        if (requestor) *requestor = ct->requestor;
        if (ct->reuse) {
            // promote at head of used list
            TAILQ_REMOVE(&cnxtrack_ips, ct, used_entry);
            TAILQ_INSERT_HEAD(&cnxtrack_ips, ct, used_entry);
            // and touch
            ct->last_used = *now;
        } else {
            // delete him
            cnxtrack_ip_del_locked(ct);
        }
    }

    mutex_unlock(&cnxtracker_lock);
    return proto;
}

/*
 * Init
 */

static unsigned inited;
void cnxtrack_init(void)
{
    if (inited++) return;
    log_init();
    ext_init();
    mutex_init();
    hash_init();
    objalloc_init();

    log_category_cnxtrack_init();
    ext_param_cnxtrack_timeout_init();

    mutex_ctor(&cnxtracker_lock, "cnxtracker");
    memset(&cnxtrack_ip_addr_unknown, 0, sizeof(cnxtrack_ip_addr_unknown));
    TAILQ_INIT(&cnxtrack_ips);
    HASH_INIT(&cnxtrack_ips_h, 1000 /* initial value of how many cnx we expect to track at a given time */, "Connection Tracking for IP");
}

void cnxtrack_fini(void)
{
    if (--inited) return;

    struct cnxtrack_ip *ct;
    mutex_lock(&cnxtracker_lock);
    while (NULL != (ct = TAILQ_FIRST(&cnxtrack_ips))) {
        cnxtrack_ip_del_locked(ct);
    }
    mutex_unlock(&cnxtracker_lock);

    HASH_DEINIT(&cnxtrack_ips_h);

    mutex_dtor(&cnxtracker_lock);
    ext_param_cnxtrack_timeout_fini();
    log_category_cnxtrack_fini();

    objalloc_fini();
    hash_fini();
    mutex_fini();
    ext_fini();
    log_fini();
}
