// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2010, SecurActive.
 *
 * This file is part of Junkie.
 *
 * Junkie is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Junkie is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Junkie.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>
#include <assert.h>
#include <signal.h>
#include <pcap.h>
#include <libguile.h>
#include "pkt_source.h"
#include "junkie/tools/objalloc.h"
#include "junkie/tools/tempstr.h"
#include "junkie/tools/mutex.h"
#include "junkie/tools/queue.h"
#include "junkie/tools/ref.h"
#include "junkie/proto/cap.h"
#include "junkie/proto/proto.h"
#include "junkie/proto/deduplication.h"
#include "junkie/tools/ext.h"
#include "plugins.h"
#include "nettrack.h"

static LIST_HEAD(pkt_sources, pkt_source) pkt_sources = LIST_HEAD_INITIALIZER(pkt_sources);
static struct mutex pkt_sources_lock;   // only valid when !terminating
static volatile sig_atomic_t terminating = 0;
static struct digest_queue *global_digests;

unsigned pkt_count; // if not 0, max number of packets to parse before exiting

static struct parser *cap_parser;

// A sequence to uniquely identifies pcap files with a numeric id (also protected with pkt_sources_lock)
// Starts at 100 so that id below 100 are available for actual interfaces.
static unsigned pcap_id_seq = 100;

#ifdef WITH_GIANT_LOCK
static struct mutex giant_lock;
#endif

static bool quit_when_done = true;
EXT_PARAM_RW(quit_when_done, "quit-when-done", bool, "Should junkie exits when the last packet source is closed ?")

LOG_CATEGORY_DEF(pkt_sources);
#undef LOG_CAT
#define LOG_CAT pkt_sources_log_category

/*
 * Tools
 */

static char const *instance_to_str(unsigned i)
{
    if (! i) return "";
    return tempstr_printf("[%u]", i);
}

static char const *pkt_source_name(struct pkt_source *pkt_source)
{
    return tempstr_printf("%s%s@%p",
        pkt_source->name,
        instance_to_str(pkt_source->instance),
        pkt_source);
}

static void pkt_source_guile_name_2_buf(struct pkt_source *pkt_source, char *buf, size_t size)
{
    snprintf(buf, size, "%s%s", pkt_source->name, instance_to_str(pkt_source->instance));
}

static char const *pkt_source_guile_name(struct pkt_source *pkt_source)
{
    char *tmp = tempstr();
    pkt_source_guile_name_2_buf(pkt_source, tmp, TEMPSTR_SIZE);
    return tmp;
}

/*
 * The possible sniffer threads
 * For now both iface and files are treated the same.
 */

static void parse_packet(u_char *pkt_source_, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct pkt_source *pkt_source = (struct pkt_source *)pkt_source_;
    SLOG(LOG_DEBUG, "Received a new packet from packet source %s, wire-len: %u", pkt_source_name(pkt_source), header->len);

    if (header->len == 0) return;   // should not happen, but does occur sometime

    pkt_source->nb_packets ++;
    pkt_source->nb_cap_bytes += header->caplen;
    pkt_source->nb_wire_bytes += header->len;

    struct frame frame = {
        .tv = header->ts,
        .cap_len = header->caplen,
        .wire_len = header->len,
        .pkt_source = pkt_source,
        .data = (uint8_t *)packet,
    };

    if (pkt_source->patch_ts) timeval_set_now(&frame.tv);

    // drop the frame if we previously saw it in the last 5ms.
    if (
        // Per iface dedup
        (pkt_source->digests && digest_queue_find(pkt_source->digests, header->caplen, (uint8_t *)packet, &header->ts)) ||
        // Additional pass if we collapse ifaces
        (collapse_ifaces && global_digests && digest_queue_find(global_digests, header->caplen, (uint8_t *)packet, &header->ts))
    ) {
        SLOG(LOG_DEBUG, "Drop duplicated packet");
        pkt_source->nb_duplicates ++;
        return;
    }

#   ifdef WITH_GIANT_LOCK
    mutex_lock(&giant_lock);
#   endif

    enter_unsafe_region();

    assert(cap_parser);
    (void)proto_parse(cap_parser, NULL, 0, (uint8_t *)&frame, frame.cap_len, frame.wire_len, &frame.tv, frame.cap_len, frame.data);

    enter_safe_region();

    if (pkt_count > 0) {
        if (0 ==
#           ifdef __GNUC__
            __sync_sub_and_fetch(&pkt_count, 1)
#           else
            --pkt_count
#           endif
        ) exit(0);
    }

#   ifdef WITH_GIANT_LOCK
    mutex_unlock(&giant_lock);
#   endif
}

static void pkt_source_del(struct pkt_source *);

static void rewind_file(struct pkt_source *pkt_source)
{
    SLOG(LOG_DEBUG, "Looping over pcap file %s", pkt_source_name(pkt_source));
    FILE *f = pcap_file(pkt_source->pcap_handle);
    if (f) {
        if (-1 == fseek(f, 24, SEEK_SET)) {
            SLOG(LOG_ERR, "Cannot rewind pcap file %s", pkt_source_name(pkt_source));
        }
    } else {
        SLOG(LOG_ERR, "Cannot get file handler for pcap %s", pkt_source_name(pkt_source));
    }
}

// Callback is responsible for updating pkt_source stats.
static void *sniffer(struct pkt_source *pkt_source, pcap_handler callback)
{
    SLOG(LOG_INFO, "Dispatching packets from packet source %s", pkt_source_name(pkt_source));
    do {
        int nb_packets = pcap_dispatch(pkt_source->pcap_handle, 100, callback, (u_char *)pkt_source);
        SLOG(LOG_DEBUG, "Got a batch of %d packets", nb_packets);
        if (nb_packets < 0) {
            if (nb_packets != -2) {
                SLOG(LOG_ALERT, "Cannot pcap_dispatch on pkt_source %s: %s", pkt_source_name(pkt_source), pcap_geterr(pkt_source->pcap_handle));
            }
            SLOG(LOG_INFO, "Stop sniffing on packet source %s (%"PRIuLEAST64" packets received)", pkt_source_name(pkt_source), pkt_source->nb_packets);
            pkt_source_del(pkt_source);
            return NULL;
        } else if (nb_packets == 0) {
            if (pkt_source->is_file) {
                if (pkt_source->loop) {
                    rewind_file(pkt_source);
                } else {
                    SLOG(LOG_INFO, "Stop sniffing from file %s (%"PRIuLEAST64" packets read)", pkt_source_name(pkt_source), pkt_source->nb_packets);
                    pkt_source_del(pkt_source);
                    return NULL;
                }
            }
        }
    } while (! terminating);

    return NULL;
}

// Beware that pkt is an in/out parameter
static void sync_times(struct timeval const *file_start, struct timeval const *replay_start, struct timeval *pkt)
{
    int64_t const pkt_age = timeval_sub(pkt, file_start);
    struct timeval tv = *replay_start;
    timeval_add_usec(&tv, pkt_age);
    // We must wait until tv
    struct timeval now;
    do {
        timeval_set_now(&now);
        int64_t wait_time = timeval_sub(&tv, &now);
#       define MIN_SLEEP 10000 /* microseconds */
#       define MAX_SLEEP 400000
        // Don't sleep less than 10ms since the sleep + parse would likely last more than that
        if (wait_time < MIN_SLEEP) break;
        // Don't sleep more than 400ms straight so that we can check for terminating flag from time to time
        usleep(MIN(MIN_SLEEP, wait_time));
    } while (! terminating);
    SLOG(LOG_DEBUG, "Patching packet TS from %s to %s", timeval_2_str(pkt), timeval_2_str(&tv));
    *pkt = tv; // Set ideal 'now' time in pkt
}

// Same as above, but try to follow original capture packet rate
static void *sniffer_rt(struct pkt_source *pkt_source, pcap_handler callback)
{
    SLOG(LOG_INFO, "Reading packets in realtime from packet source %s", pkt_source_name(pkt_source));
    struct timeval file_start, replay_start;
    timeval_reset(&file_start);
    timeval_set_now(&replay_start);

    do {
        struct pcap_pkthdr *pkt_hdr;
        const unsigned char *packet;
        int res = pcap_next_ex(pkt_source->pcap_handle, &pkt_hdr, &packet);
        if (res < 0) {
            if (res == -2) {    // end of file
                assert(pkt_source->is_file);
                if (pkt_source->loop) {
                    rewind_file(pkt_source);
                    timeval_set_now(&replay_start);
                    continue;
                } else {
                    SLOG(LOG_INFO, "Stop sniffing from %s (%"PRIuLEAST64" packets read)", pkt_source_name(pkt_source), pkt_source->nb_packets);
                    break;
                }
            } else { // error
                SLOG(LOG_ERR, "Cannot pcap_dispatch on pkt_source %s: %s", pkt_source_name(pkt_source), pcap_geterr(pkt_source->pcap_handle));
                break;
            }
        }
        assert(res == 1);   // 0 should not happen
        if (pkt_hdr->ts.tv_sec == 0) continue;   // should not happen, but does occur sometime (same goes for all other pcap header fields)
        if (! timeval_is_set(&file_start)) file_start = pkt_hdr->ts;
        sync_times(&file_start, &replay_start, &pkt_hdr->ts);
        if (terminating) break;
        callback((void *)pkt_source, pkt_hdr, packet);
    } while (1);

    SLOG(LOG_INFO, "Stop sniffing on packet source %s (%"PRIuLEAST64" packets received)", pkt_source_name(pkt_source), pkt_source->nb_packets);
    pkt_source_del(pkt_source);
    return NULL;
}

static void *iface_sniffer(void *pkt_source_)
{
    struct pkt_source *pkt_source = pkt_source_;
    set_thread_name(tempstr_printf("J-snif-%s[%u]", pkt_source->name, pkt_source->instance));
    return sniffer(pkt_source, parse_packet);
}

static void *file_sniffer(void *pkt_source_)
{
    struct pkt_source *pkt_source = pkt_source_;
    set_thread_name(tempstr_printf("J-read-%s[%u]", pkt_source->name, pkt_source->instance));
    return sniffer(pkt_source, parse_packet);
}

static void *file_sniffer_rt(void *pkt_source_)
{
    struct pkt_source *pkt_source = pkt_source_;
    set_thread_name(tempstr_printf("J-read-%s[%u]", pkt_source->name, pkt_source->instance));
    return sniffer_rt(pkt_source, parse_packet);
}

/*
 * Ctor/Dtor of pkt_sources
 */

static int set_filter(pcap_t *pcap_handle, char const *filter)
{
    struct bpf_program fp;

    if (filter[0] == '\0') return 0;

    if (0 != pcap_compile(pcap_handle, &fp, filter, 1, 0)) {
        SLOG(LOG_ERR, "Cannot parse filter %s: %s\n", filter, pcap_geterr(pcap_handle));
        return -1;
    }
    if (0 != pcap_setfilter(pcap_handle, &fp)) {
        SLOG(LOG_ERR, "Cannot install filter %s: %s\n", filter, pcap_geterr(pcap_handle));
        return -1;
    }

    return 0;
}

/* We start all sniffer thread in guile mode so that plugins that require guile mode are not
 * forced to enter guile mode packet by packet. */
static void *start_guile_sniffer(void *pkt_source_)
{
    struct pkt_source *pkt_source = pkt_source_;
    return scm_with_guile(pkt_source->sniffer_fun, pkt_source);
}

// TODO: add a parameter to enable/disable deduplication
static int pkt_source_ctor(struct pkt_source *pkt_source, char const *name, pcap_t *pcap_handle, void *(*sniffer)(void *), bool is_file, bool patch_ts, uint8_t dev_id, char const *filter, bool loop)
{
    SLOG(LOG_DEBUG, "Construct pkt_source@%p of name %s and dev_id %"PRIu8, pkt_source, name, dev_id);
    int ret = 0;

    snprintf(pkt_source->name, sizeof(pkt_source->name), "%s", name);
    pkt_source->instance = 0;
    pkt_source->pcap_handle = pcap_handle;
    pkt_source->nb_packets = 0;
    pkt_source->nb_duplicates = 0;
    pkt_source->nb_cap_bytes = 0;
    pkt_source->nb_wire_bytes = 0;
    pkt_source->is_file = is_file;
    pkt_source->patch_ts = patch_ts;
    pkt_source->loop = loop;
    pkt_source->filter = filter ? objalloc_strdup(filter) : NULL;
    pkt_source->sniffer_fun = sniffer;
    pkt_source->digests = digest_queue_get(dev_id); // if we can't have a deduplicator, let's go without one!

    mutex_lock(&pkt_sources_lock);
    if (terminating) {
        ret = -1;
        goto unlock_quit;
    }

    struct pkt_source *other;
    LIST_FOREACH(other, &pkt_sources, entry) {  // Unify name by computing instance number
        if (0 == strcmp(name, other->name) && other->instance >= pkt_source->instance) pkt_source->instance = other->instance+1;
    }

    pkt_source->dev_id = dev_id;
    LIST_INSERT_HEAD(&pkt_sources, pkt_source, entry);

    int err = pthread_create(&pkt_source->sniffer_pth, NULL, start_guile_sniffer, pkt_source);
    if (err) {
        SLOG(LOG_ERR, "Cannot start sniffer thread on pkt_source %s[?]@%p: %s", pkt_source->name, pkt_source, strerror(err));  // Notice that pkt_source->instance is not inited yet
        LIST_REMOVE(pkt_source, entry);
        ret = -1;
        goto unlock_quit;
    }
    pthread_detach(pkt_source->sniffer_pth);

unlock_quit:
    mutex_unlock(&pkt_sources_lock);
    return ret;
}

static struct pkt_source *pkt_source_new(char const *name, pcap_t *pcap_handle, void *(*sniffer)(void *), bool is_file, bool patch_ts, uint8_t dev_id, char const *filter, bool loop)
{
    struct pkt_source *pkt_source = objalloc(sizeof(*pkt_source), "pkt_sources");
    if (! pkt_source) return NULL;

    if (0 != pkt_source_ctor(pkt_source, name, pcap_handle, sniffer, is_file, patch_ts, dev_id, filter, loop)) {
        objfree(pkt_source);
        pkt_source = NULL;
    }

    return pkt_source;
}

static struct pkt_source *pkt_source_new_file(char const *filename, char const *filter, bool rt, bool patch_ts, bool loop)
{
    char errbuf[PCAP_ERRBUF_SIZE] = "";

    SLOG(LOG_DEBUG, "Opening pcap file '%s' with filter %s", filename, filter ? filter:"NONE");

    pcap_t *handle = pcap_open_offline(filename, errbuf);
    if (! handle) {
        SLOG(LOG_CRIT, "Cannot open pcap file '%s': %s", filename, errbuf);
        return NULL;
    }
    if (errbuf[0] != '\0') {
        SLOG(LOG_WARNING, "While opening pcap file '%s': %s", filename, errbuf);
    }

    char const *basename = filename;
    for (char const *c = filename; *c != '\0'; c++) {
        if (*c == '/') basename = c+1;
    }

    if (filter && 0 != set_filter(handle, filter)) {
        pcap_close(handle);
        return NULL;
    }

    void *(*sniff)(void *) = rt ? file_sniffer_rt : file_sniffer;
    struct pkt_source *pkt_source = pkt_source_new(basename, handle, sniff, true, patch_ts, pcap_id_seq++, filter, loop);
    if (! pkt_source) {
        pcap_close(handle);
    }

    return pkt_source;
}

static void quit_if_nothing_opened(void)
{
    bool do_exit = false;
    mutex_lock(&pkt_sources_lock);
    if (LIST_EMPTY(&pkt_sources)) {
        EXT_LOCK(quit_when_done);
        do_exit = quit_when_done;
        EXT_UNLOCK(quit_when_done);
    }
    mutex_unlock(&pkt_sources_lock);

    if (do_exit) exit(0);
}

// We use the number that folows ifname as a device_id. Should work as intended in most cases
// (ie. as long as these are <100 and we don't listen simultaneously eth4 and dummy4, for instance)
static uint8_t dev_id_of_ifname(char const *ifname)
{
    char const *c;
    for (c = ifname; *c && !isdigit(*c); c++) ;
    return strtoul(c, NULL, 10);
}

static struct pkt_source *pkt_source_new_if(char const *ifname, bool promisc, char const *filter, size_t snaplen, int buffer_size)
{
    char errbuf[PCAP_ERRBUF_SIZE] = "";

    SLOG(LOG_INFO, "Opening pcap device '%s'%s with filter %s and buffer size %d", ifname, promisc ? " in promiscuous mode":"", filter ? filter:"NONE", buffer_size);

    if (! snaplen) snaplen = 65535;

    pcap_t *handle = pcap_create(ifname, errbuf);
    if (! handle) {
        SLOG(LOG_ALERT, "Cannot create handle for device '%s': %s", ifname, errbuf);
        goto err2;
    }

    if (buffer_size > 0 && 0 != pcap_set_buffer_size(handle, buffer_size)) {
        SLOG(LOG_ALERT, "Cannot set buffer size for packet source %s to %d bytes: %s", ifname, buffer_size, pcap_geterr(handle));
        goto err1;
    }

    if (0 != pcap_set_promisc(handle, promisc)) {
        SLOG(LOG_ALERT, "Cannot set promiscuous mode to %s for packet source %s: %s", promisc ? "true":"false", ifname, pcap_geterr(handle));
        goto err1;
    }

    if (0 != pcap_set_snaplen(handle, snaplen)) {
        SLOG(LOG_ALERT, "Cannot set snaplen to %zu for packet source %s: %s", snaplen, ifname, pcap_geterr(handle));
        goto err1;
    }

    if (0 != pcap_set_timeout(handle, 1000)) {
        SLOG(LOG_ALERT, "Cannot set timeout for packet source %s: %s", ifname, pcap_geterr(handle));
        goto err1;
    }

    if (0 != pcap_activate(handle)) {
        SLOG(LOG_ALERT, "Cannot activate packet source %s: %s", ifname, pcap_geterr(handle));
        goto err1;
    }

    if (filter && 0 != set_filter(handle, filter)) {
        pcap_close(handle);
        return NULL;
    }

    uint8_t dev_id = dev_id_of_ifname(ifname);
    struct pkt_source *pkt_source = pkt_source_new(ifname, handle, iface_sniffer, false, false, dev_id, filter, false);
    if (! pkt_source) {
        pcap_close(handle);
    }

    return pkt_source;
err1:
    pcap_close(handle);
err2:
    quit_if_nothing_opened();
    return NULL;
}

// Caller must own pkt_sources_lock
static void pkt_source_dtor(struct pkt_source *pkt_source)
{
    SLOG(LOG_DEBUG, "Closing packet source %s (parsed %"PRIu64" packets)", pkt_source_name(pkt_source), pkt_source->nb_packets);

    mutex_lock(&pkt_sources_lock);
    LIST_REMOVE(pkt_source, entry);
    mutex_unlock(&pkt_sources_lock);

    if (pkt_source->pcap_handle) {
        pcap_close(pkt_source->pcap_handle);
        pkt_source->pcap_handle = NULL;
    }
    if (pkt_source->filter) {
        objfree(pkt_source->filter);
        pkt_source->filter = NULL;
    }
    digest_queue_unref(&pkt_source->digests);
}

static void pkt_source_del(struct pkt_source *pkt_source)
{
    pkt_source_dtor(pkt_source);
    objfree(pkt_source);
    if (! terminating) quit_if_nothing_opened();
}

// Caller must own pkt_sources_lock
static void pkt_source_terminate(struct pkt_source *pkt_source)
{
    SLOG(LOG_DEBUG, "Terminating packet source '%s' after %"PRIu64" packets (%"PRIu64" dups)", pkt_source_name(pkt_source), pkt_source->nb_packets, pkt_source->nb_duplicates);
    pcap_breakloop(pkt_source->pcap_handle);
}

// Caller must own pkt_sources_lock
static void pkt_source_terminate_all(void)
{
    struct pkt_source *pkt_source, *tmp;
    LIST_FOREACH_SAFE(pkt_source, &pkt_sources, entry, tmp) {
        pkt_source_terminate(pkt_source);
    }
}

/*
 * Guile access functions
 */

static struct ext_function sg_list_ifaces;
static SCM g_list_ifaces(void)
{
    SCM ret = SCM_EOL;
    char errbuf[PCAP_ERRBUF_SIZE] = "";
    pcap_if_t *alldevs;

    if (0 != pcap_findalldevs(&alldevs, errbuf)) {
        SLOG(LOG_ERR, "Cannot pcap_findalldevs: %s", errbuf);
        return SCM_UNSPECIFIED;
    }

    for (pcap_if_t *dev = alldevs; dev; dev = dev->next) {
        ret = scm_cons(scm_from_locale_string(dev->name), ret);
    }
    pcap_freealldevs(alldevs);

    return ret;
}

// Caller must own pkt_sources_lock
static struct pkt_source *pkt_source_of_scm(SCM ifname_)
{
    char name[PATH_MAX];
    char *ifname = scm_to_tempstr(ifname_);

    struct pkt_source *pkt_source;
    LIST_FOREACH(pkt_source, &pkt_sources, entry) {
        pkt_source_guile_name_2_buf(pkt_source, name, sizeof(name));
        if (0 == strcmp(ifname, name)) break;
    }
    return pkt_source;
}

static struct ext_function sg_open_iface;
static SCM g_open_iface(SCM ifname_, SCM promisc_, SCM filter_, SCM snaplen_, SCM buffer_size_)
{
    char *ifname = scm_to_tempstr(ifname_);
    bool const promisc = SCM_UNBNDP(promisc_) || scm_to_bool(promisc_);
    char const *filter = SCM_UNBNDP(filter_) ? NULL : scm_to_tempstr(filter_);
    size_t const snaplen = SCM_UNBNDP(snaplen_) ? 0 : scm_to_size_t(snaplen_);
    int const buffer_size = SCM_UNBNDP(buffer_size_) ? 0 : scm_to_int(buffer_size_);

    struct pkt_source *pkt_source = pkt_source_new_if(ifname, promisc, filter, snaplen, buffer_size);
    return pkt_source ? scm_from_locale_string(pkt_source_guile_name(pkt_source)) : SCM_UNSPECIFIED;
}

static struct ext_function sg_open_pcap;
static SCM g_open_pcap(SCM filename_, SCM rt_, SCM filter_, SCM patch_ts_, SCM loop_)
{
    char const *filename = scm_to_tempstr(filename_);
    char const *filter = SCM_UNBNDP(filter_) ? NULL : scm_to_tempstr(filter_);
    bool const rt = SCM_UNBNDP(rt_) ? false : scm_to_bool(rt_);
    bool const patch_ts = SCM_UNBNDP(patch_ts_) ? false : scm_to_bool(patch_ts_);
    bool const loop = SCM_UNBNDP(loop_) ? false : scm_to_bool(loop_);

    struct pkt_source *pkt_source = pkt_source_new_file(filename, filter, rt, patch_ts, loop);
    return pkt_source ? SCM_BOOL_T : SCM_BOOL_F;
}

static struct ext_function sg_close_iface;
static SCM g_close_iface(SCM ifname_)
{
    mutex_lock(&pkt_sources_lock);
    struct pkt_source *pkt_source = pkt_source_of_scm(ifname_);
    SCM ret = SCM_BOOL_F;

    if (pkt_source) {
        pkt_source_terminate(pkt_source);
        ret = SCM_BOOL_T;
    }

    mutex_unlock(&pkt_sources_lock);
    return ret;
}

static struct ext_function sg_iface_names;
static SCM g_iface_names(void)
{
    char name[PATH_MAX];
    SCM ret = SCM_EOL;

    struct pkt_source *pkt_source;

    LIST_FOREACH(pkt_source, &pkt_sources, entry) {
        pkt_source_guile_name_2_buf(pkt_source, name, sizeof(name));
        ret = scm_cons(scm_from_locale_string(name), ret);
    }

    return ret;
}

static SCM id_sym;
static SCM nb_packets_sym;
static SCM nb_duplicates_sym;
static SCM tot_received_sym;
static SCM tot_dropped_sym;
static SCM nb_cap_bytes_sym;
static SCM nb_wire_bytes_sym;
static SCM filep_sym;
static SCM filter_sym;

static struct ext_function sg_iface_stats;
static SCM g_iface_stats(SCM ifname_)
{
    mutex_lock(&pkt_sources_lock);
    struct pkt_source *pkt_source = pkt_source_of_scm(ifname_);
    SCM ret = SCM_UNSPECIFIED;

    if (! pkt_source) goto err;

    struct pcap_stat stats;
    bool const have_stats = 0 == pcap_stats(pkt_source->pcap_handle, &stats);
    if (! have_stats) {
        SLOG(LOG_WARNING, "Cannot read stats for packet source %s: %s\n", pkt_source_name(pkt_source), pcap_geterr(pkt_source->pcap_handle));
    }

    ret = scm_list_n(
        scm_cons(id_sym,            scm_from_uint8(pkt_source->dev_id)),
        scm_cons(nb_packets_sym,    scm_from_uint64(pkt_source->nb_packets)),
        scm_cons(nb_duplicates_sym, scm_from_uint64(pkt_source->nb_duplicates)),
        scm_cons(tot_received_sym,  have_stats ? scm_from_uint(stats.ps_recv) : scm_from_uint64(pkt_source->nb_packets)),
        scm_cons(tot_dropped_sym,   have_stats ? scm_from_uint(stats.ps_drop) : scm_from_int(0)),
        scm_cons(nb_cap_bytes_sym,  scm_from_uint64(pkt_source->nb_cap_bytes)),
        scm_cons(nb_wire_bytes_sym, scm_from_uint64(pkt_source->nb_wire_bytes)),
        scm_cons(filep_sym,         scm_from_bool(pkt_source->is_file)),
        pkt_source->filter ?
            scm_cons(filter_sym,    scm_from_latin1_string(pkt_source->filter)) :
            SCM_UNDEFINED,
        SCM_UNDEFINED);

err:
    mutex_unlock(&pkt_sources_lock);
    return ret;
}

// The first thing to do when quitting is to stop parsing traffic
static unsigned inited;
void pkt_source_init(void)
{
    if (inited++) return;
    mutex_init();
    ext_init();
    objalloc_init();
    ref_init();
    digest_init();

#   define IFACE_ALL 255
    global_digests = digest_queue_get(IFACE_ALL);

#   ifdef WITH_GIANT_LOCK
    mutex_ctor(&giant_lock, "Giant Lock");
#   endif

    mutex_ctor(&pkt_sources_lock, "pkt_sources");

    id_sym                = scm_permanent_object(scm_from_latin1_symbol("id"));
    nb_packets_sym        = scm_permanent_object(scm_from_latin1_symbol("nb-packets"));
    nb_duplicates_sym     = scm_permanent_object(scm_from_latin1_symbol("nb-duplicates"));
    tot_received_sym      = scm_permanent_object(scm_from_latin1_symbol("tot-received"));
    tot_dropped_sym       = scm_permanent_object(scm_from_latin1_symbol("tot-dropped"));
    nb_cap_bytes_sym      = scm_permanent_object(scm_from_latin1_symbol("nb-cap-bytes"));
    nb_wire_bytes_sym     = scm_permanent_object(scm_from_latin1_symbol("nb-wire-bytes"));
    filep_sym             = scm_permanent_object(scm_from_latin1_symbol("file?"));
    filter_sym            = scm_permanent_object(scm_from_latin1_symbol("filter"));

    ext_param_quit_when_done_init();
    log_category_pkt_sources_init();

    cap_parser = proto_cap->ops->parser_new(proto_cap);

    ext_function_ctor(&sg_list_ifaces,
        "list-ifaces", 0, 0, 0, g_list_ifaces,
        "(list-ifaces): returns a list of all ifaces that can be opened for sniffing.\n"
        "Note that if you don't have sufficient permission to open a device then this device\n"
        "    will not appear in this list.\n"
        "See also (? 'open-iface) to start sniffing an interface.\n");

    ext_function_ctor(&sg_open_iface,
        "open-iface", 1, 4, 0, g_open_iface,
        "(open-iface \"iface-name\"): open the given iface, and set it in promiscuous mode.\n"
        "(open-iface \"iface-name\" #f): open the given iface without setting it\n"
        "    in promiscuous mode.\n"
        "(open-iface \"iface-name\" #t \"filter\"): open the given iface in promiscuous mode,\n"
        "    with the given packet filter.\n"
        "(open-iface \"iface-name\" #t \"filter\" 90): same as above, but capture only the first\n"
        "    90 bytes of each packet. Use 0 for all bytes (the default).\n"
        "(open-iface \"iface-name\" #t \"[filter]\" 90 (* 10 1024 1024)): same as above, using\n"
        "    a buffer size of 10Mb (instead of system default).\n"
        "Will return #t or #f depending on the success of the operation.\n"
        "See also (? 'list-ifaces) to have a list of all openable ifaces,\n"
        "    and (? 'close-iface) to close a given iface\n");

    ext_function_ctor(&sg_close_iface,
        "close-iface", 1, 0, 0, g_close_iface,
        "(close-iface \"iface-name\"): stop sniffing a previously opened iface.\n"
        "See also (? 'open-iface).\n");

    ext_function_ctor(&sg_open_pcap,
        "open-pcap", 1, 4, 0, g_open_pcap,
        "(open-pcap \"pcap-file\"): read the content of this pcap file, full speed.\n"
        "(open-pcap \"pcap-file\" #t): read this pcap file using its packet rate rather than full speed.\n"
        "(open-pcap \"pcap-file\" #f \"filter\"): same as above, applying given filter.\n"
        "(open-pcap \"pcap-file\" #f \"filter\" #t): same as above, patching current localtime on every packets.\n"
        "(open-pcap \"pcap-file\" #f \"filter\" #t #t): same as above, looping the pcap.\n"
        "Will return #t or #f according to the status of the operation.\n"
        "See also (? 'open-iface)\n");

    ext_function_ctor(&sg_iface_names,
        "iface-names", 0, 0, 0, g_iface_names,
        "(iface-names): returns the list of currently opened interfaces.\n"
        "See also (? 'open-iface).\n");

    ext_function_ctor(&sg_iface_stats,
        "iface-stats", 1, 0, 0, g_iface_stats,
        "(iface-stats \"iface-name\"): return detailed statistics about that packet source.\n"
        "See also (? 'get-ifaces).\n");
}

void pkt_source_fini(void)
{
    if (--inited) return;

    mutex_lock(&pkt_sources_lock);
    terminating = 1;
    pkt_source_terminate_all();
    mutex_unlock(&pkt_sources_lock);

    // Waiting for the dispatcher threads to terminate
    // We don't wait forever since the thread executing this code might be the sniffer thread itself. (FIXME) (or change specs (junkie should perhaps not quit ?))
    for (unsigned nb_try = 0; nb_try < 3; nb_try ++) {
        mutex_lock(&pkt_sources_lock);
        bool is_empty = LIST_EMPTY(&pkt_sources);
        if (! is_empty) SLOG(LOG_DEBUG, "Waiting for termination of packet source '%s'", pkt_source_name(LIST_FIRST(&pkt_sources)));
        mutex_unlock(&pkt_sources_lock);
        if (is_empty) break;
        sleep(1);
    }

    parser_unref(&cap_parser);
    mutex_dtor(&pkt_sources_lock);

#   ifdef WITH_GIANT_LOCK
    mutex_dtor(&giant_lock);
#   endif

    log_category_pkt_sources_fini();
    ext_param_quit_when_done_fini();

    digest_queue_unref(&global_digests);

    digest_fini();
    ref_fini();
    mutex_fini();
    ext_fini();
    objalloc_fini();
}
