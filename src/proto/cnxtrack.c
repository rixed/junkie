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
    bool reuse;
    struct timeval last_used;
};

static int cnxtrack_ip_ctor(struct cnxtrack_ip *ct, unsigned ip_proto, struct ip_addr const *src, uint16_t src_port, struct ip_addr const *dst, uint16_t dst_port, bool reuse, struct proto *proto, struct timeval const *now)
{
    SLOG(LOG_DEBUG, "Construct cnxtrack_ip@%p for proto %u, %s:%"PRIu16"->%s:%"PRIu16" for %s",
        ct, ip_proto, ip_addr_2_str(src), src_port, ip_addr_2_str(dst), dst_port, proto->name);

    ct->key.ip.protocol = ip_proto;
    ct->key.ip.addr[0] = *src;
    ct->key.ip.addr[1] = *dst;
    ct->key.port.port[0] = src_port;
    ct->key.port.port[1] = dst_port;
    ct->proto = proto;
    ct->reuse = reuse;
    ct->last_used = *now;

    mutex_lock(&cnxtracker_lock);
    TAILQ_INSERT_HEAD(&cnxtrack_ips, ct, used_entry);
    HASH_INSERT(&cnxtrack_ips_h, ct, &ct->key, h_entry);
    mutex_unlock(&cnxtracker_lock);

    return 0;
}

struct cnxtrack_ip *cnxtrack_ip_new(unsigned ip_proto, struct ip_addr const *src, uint16_t src_port, struct ip_addr const *dst, uint16_t dst_port, bool reuse, struct proto *proto, struct timeval const *now)
{
    MALLOCER(cnxtracks);
    struct cnxtrack_ip *ct = MALLOC(cnxtracks, sizeof(*ct));
    if (! ct) return NULL;
    if (0 != cnxtrack_ip_ctor(ct, ip_proto, src, src_port, dst, dst_port, reuse, proto, now)) {
        FREE(ct);
        return NULL;
    }
    return ct;
}

static void cnxtrack_ip_dtor(struct cnxtrack_ip *ct)
{
    SLOG(LOG_DEBUG, "Destruct cnxtrack_ip@%p", ct);

    mutex_lock(&cnxtracker_lock);
    HASH_REMOVE(&cnxtrack_ips_h, ct, h_entry);
    TAILQ_REMOVE(&cnxtrack_ips, ct, used_entry);
    mutex_unlock(&cnxtracker_lock);
}

void cnxtrack_ip_del(struct cnxtrack_ip *ct)
{
    cnxtrack_ip_dtor(ct);
    FREE(ct);
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
        cnxtrack_ip_del(ct);
    }
}

// caller must own cnxtracker_lock
static struct cnxtrack_ip *lll_lookup(unsigned ip_proto, struct ip_addr const *src, uint16_t src_port, struct ip_addr const *dst, uint16_t dst_port)
{
    struct cnxtrack_ip_key key = {
        .ip = {
            .protocol = ip_proto,
            .addr = { *src, *dst },
        },
        .port = {
            .port = { src_port, dst_port },
        },
    };
    struct cnxtrack_ip *ct;
    HASH_LOOKUP(ct, &cnxtrack_ips_h, &key, key, h_entry);
    return ct;
}

static struct cnxtrack_ip *ll_lookup(unsigned ip_proto, struct ip_addr const *src, uint16_t src_port, struct ip_addr const *dst, uint16_t dst_port)
{
    struct cnxtrack_ip *ct = lll_lookup(ip_proto, src, src_port, dst, dst_port);
    if (ct) return ct;
    return lll_lookup(ip_proto, dst, dst_port, src, src_port);
}

struct proto *cnxtrack_ip_lookup(unsigned ip_proto, struct ip_addr const *src, uint16_t src_port, struct ip_addr const *dst, uint16_t dst_port, struct timeval const *now)
{
    struct proto *proto = NULL;

    SLOG(LOG_DEBUG, "Lookup tracked cnx for proto %u, %s:%"PRIu16"->%s:%"PRIu16,
        ip_proto, ip_addr_2_str(src), src_port, ip_addr_2_str(dst), dst_port);

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
    ct = ll_lookup(ip_proto, src, src_port, dst, dst_port);
    if (ct) goto done;

    // Maybe we lacked one IP address?
    if (src != &cnxtrack_ip_addr_unknown) {
        ct = ll_lookup(ip_proto, &cnxtrack_ip_addr_unknown, src_port, dst, dst_port);
        if (ct) goto done;
    }
    if (dst != &cnxtrack_ip_addr_unknown) {
        ct = ll_lookup(ip_proto, src, src_port, &cnxtrack_ip_addr_unknown, dst_port);
        if (ct) goto done;
    }

    // Maybe we lacked one port then?
    if (src_port != PORT_UNKNOWN) {
        ct = ll_lookup(ip_proto, src, PORT_UNKNOWN, dst, dst_port);
        if (ct) goto done;
    }
    if (dst_port != PORT_UNKNOWN) {
        ct = ll_lookup(ip_proto, src, src_port, dst, PORT_UNKNOWN);
        if (ct) goto done;
    }

    // It's becoming problematic. Maybe we had only one peer then?
    if (src != &cnxtrack_ip_addr_unknown || src_port != PORT_UNKNOWN) {
        ct = ll_lookup(ip_proto, &cnxtrack_ip_addr_unknown, PORT_UNKNOWN, dst, dst_port);
        if (ct) goto done;
    }
    if (dst != &cnxtrack_ip_addr_unknown || dst_port != PORT_UNKNOWN) {
        ct = ll_lookup(ip_proto, src, src_port, &cnxtrack_ip_addr_unknown, PORT_UNKNOWN);
        if (ct) goto done;
    }

    // I'm afraid we don't know this stream. 14 hash search for nothing...

done:
    if (ct) {
        proto = ct->proto;
        if (ct->reuse) {
            // promote at head of used list
            TAILQ_REMOVE(&cnxtrack_ips, ct, used_entry);
            TAILQ_INSERT_HEAD(&cnxtrack_ips, ct, used_entry);
            // and touch
            ct->last_used = *now;
        } else {
            // delete him
            cnxtrack_ip_del(ct);
        }
    }

    mutex_unlock(&cnxtracker_lock);
    return proto;
}

/*
 * Init
 */

void cnxtrack_init(void)
{
    log_category_cnxtrack_init();
    ext_param_cnxtrack_timeout_init();

    mutex_ctor(&cnxtracker_lock, "cnxtracker");
    memset(&cnxtrack_ip_addr_unknown, 0, sizeof(cnxtrack_ip_addr_unknown));
    TAILQ_INIT(&cnxtrack_ips);
    HASH_INIT(&cnxtrack_ips_h, 1000 /* initial value of how many cnx we expect to track at a given time */, "Connection Tracking for IP");
}

void cnxtrack_fini(void)
{
    mutex_dtor(&cnxtracker_lock);

    struct cnxtrack_ip *ct;
    while (NULL != (ct = TAILQ_FIRST(&cnxtrack_ips))) {
        cnxtrack_ip_del(ct);
    }

    HASH_DEINIT(&cnxtrack_ips_h);

    ext_param_cnxtrack_timeout_fini();
    log_category_cnxtrack_fini();
}
