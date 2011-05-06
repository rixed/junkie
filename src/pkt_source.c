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
#include <junkie/tools/mallocer.h>
#include <junkie/tools/tempstr.h>
#include <junkie/tools/mutex.h>
#include <junkie/tools/queue.h>
#include <junkie/proto/cap.h>
#include <junkie/proto/proto.h>
#include <junkie/tools/ext.h>
#include "plugins.h"
#include "digest_queue.h"

static char const Id[] = "$Id: 39b7df38bd54e40f37c33511c3ab617d6b719437 $";

static LIST_HEAD(pkt_sources, pkt_source) pkt_sources = LIST_HEAD_INITIALIZER(pkt_sources);
static struct mutex pkt_sources_lock;
static volatile sig_atomic_t terminating = 0;

// Giant Lock to ensure only one parse is running simultaneously (TODO: finer grained lock)
static struct mutex cap_parser_lock;

static struct parser *cap_parser = NULL;

// A sequence to uniquely identifies pcap files with a numeric id (also protected with pkt_sources_lock)
// Starts at 100 so that id below 100 are available for actual interfaces.
static unsigned pcap_id_seq = 100;

static int dup_detection_delay = 5000;  // microseconds
EXT_PARAM_RW(dup_detection_delay, "dup-detection-delay", int, "Number of microseconds between two packets that can't be duplicates")

static struct digest_queue *digests;

// Som estats about the used of the digest queue. Protected with digest_stats_lock.
static struct mutex digest_stats_lock;
static uint_least64_t searched_digests, nb_dup_found, nb_nodup_found, nb_eol_found;

static void reset_dedup_stats(void)
{
    searched_digests = nb_dup_found = nb_nodup_found = nb_eol_found = 0;
}

static unsigned nb_digests = 100;
// The seter is a little special as it rebuild the digest queue
static struct ext_param ext_param_nb_digests;
static SCM g_ext_param_set_nb_digests(SCM v)
{
    SCM ret = SCM_BOOL_F;
    SLOG(LOG_DEBUG, "Setting value for nb_digests");
    assert(&ext_param_nb_digests.bound);
    scm_dynwind_begin(0);
    pthread_mutex_lock(&ext_param_nb_digests.mutex);
    scm_dynwind_unwind_handler(pthread_mutex_unlock_, &ext_param_nb_digests.mutex, SCM_F_WIND_EXPLICITLY);

    unsigned new_nb_digests = scm_to_uint(v);
    struct digest_queue *new_digests = digest_queue_new(new_nb_digests);
    if (new_digests) {
        // We must prevent anyone to use the digest queue!
        mutex_lock(&cap_parser_lock);
        scm_dynwind_unwind_handler(pthread_mutex_unlock_, &cap_parser_lock.mutex, SCM_F_WIND_EXPLICITLY);
        if (digests) digest_queue_del(digests);
        nb_digests = new_nb_digests;
        digests = new_digests;
        ret = SCM_BOOL_T;
    }
    scm_dynwind_end();
    return ret;
}
EXT_PARAM_GET(nb_digests, uint)
EXT_PARAM_STRUCT_RW(nb_digests, "nb-digests", "How many digests do we keep for deduplication")
EXT_PARAM_CTORDTOR(nb_digests)

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
 * For now both iface anf files are treated the same.
 */

static int parser_callbacks(struct proto_info const *last, size_t tot_cap_len, uint8_t const *tot_packet)
{
    struct plugin *plugin;
    mutex_lock(&plugins_mutex);
    LIST_FOREACH(plugin, &plugins, entry) {
        if (plugin->parse_callback) plugin->parse_callback(last, tot_cap_len, tot_packet);
    }
    mutex_unlock(&plugins_mutex);
    return 0;
}

static void update_dedup_stats(unsigned nb_searched, unsigned dup_found, unsigned nodup_found, unsigned eol_found)
{
    mutex_lock(&digest_stats_lock);
    uint_least64_t const prev = searched_digests;
    searched_digests += nb_searched;
    if (searched_digests < prev) {
        reset_dedup_stats();
    }
    nb_dup_found += dup_found;
    nb_nodup_found += nodup_found;
    nb_eol_found += eol_found;
    mutex_unlock(&digest_stats_lock);
}

// drop the frame if we previously saw it in the last 5ms.
// owner must own cap_parser_lock
static int frame_mirror_drop(struct frame *frame, struct digest_queue *q)
{
    if (! dup_detection_delay) return 0;

    uint8_t digest[DIGEST_SIZE];
    digest_frame(digest, frame);

    unsigned i;
    for (i = 0; i < q->size; i++) {
        int j = (q->idx - i + q->size) % q->size;

        if (!timeval_is_set(&q->digests[j].tv) || timeval_sub(&frame->tv, &q->digests[j].tv) > dup_detection_delay)
            break;

        if (0 == memcmp(q->digests[j].digest, digest, DIGEST_SIZE)) {
            q->digests[j].tv = frame->tv;
            SLOG(LOG_DEBUG, "@%d -- Identical frame, possible duplicate", j);
            update_dedup_stats(i, 1, 0, 0);
            return 1;
        }
    }

    update_dedup_stats(i, 0, i < q->size, i >= q->size);

    digest_queue_push(q, digest, frame);
    return 0;
}

static void parse_packet(u_char *pkt_source_, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct pkt_source *pkt_source = (struct pkt_source *)pkt_source_;
    SLOG(LOG_DEBUG, "Received a new packet from packet source %s, wire-len: %u", pkt_source_name(pkt_source), header->len);

    if (header->len == 0) return;   // should not happen, but does occur sometime

    pkt_source->nb_packets ++;
    pkt_source->nb_cap_bytes += header->caplen;
    pkt_source->nb_wire_bytes += header->len;

    mutex_lock(&cap_parser_lock);

    if (! cap_parser) {
        cap_parser = proto_cap->ops->parser_new(proto_cap, &header->ts);
        if (! cap_parser) {
            SLOG(LOG_ERR, "Cannot construct capture parser");
            mutex_unlock(&cap_parser_lock);
            return;
        }
    }

    // must own cap_parser_lock since we are going to lock all protos
    unsigned nb_victims = proto_timeout(&header->ts);

    if (nb_victims) SLOG(LOG_DEBUG, "Timeouted %u parsers", nb_victims);

    struct frame frame = {
        .tv = header->ts,
        .cap_len = header->caplen,
        .wire_len = header->len,
        .pkt_source = pkt_source,
        .data = (uint8_t *)packet,
    };

    if (digests && frame_mirror_drop(&frame, digests)) {
        SLOG(LOG_DEBUG, "Drop dupplicated packet");
        pkt_source->nb_duplicates ++;
        mutex_unlock(&cap_parser_lock);
        return;
    }

    // due to the frame structure, cap parser does not need cap_len nor wire_len
    (void)proto_parse(cap_parser, NULL, 0, (uint8_t *)&frame, frame.cap_len, frame.wire_len, &header->ts, parser_callbacks, frame.cap_len, frame.data);

    mux_subparser_kill_doomed();

    mutex_unlock(&cap_parser_lock);
}

static void pkt_source_del(struct pkt_source *);

// Callback is responsible for updating pkt_source stats.
static void *sniffer(struct pkt_source *pkt_source, pcap_handler callback)
{
    SLOG(LOG_INFO, "Dispatching packets from packet source %s", pkt_source_name(pkt_source));
    do {
        int nb_packets = pcap_dispatch(pkt_source->pcap_handle, 100, callback, (u_char *)pkt_source);
        SLOG(LOG_DEBUG, "Got a batch of %d packets", nb_packets);
        if (nb_packets < 0) {
            if (nb_packets != -2) {
                SLOG(LOG_ERR, "Cannot pcap_dispatch on pkt_source %s: %s", pkt_source_name(pkt_source), pcap_geterr(pkt_source->pcap_handle));
            }
            SLOG(LOG_INFO, "Stop sniffing on packet source %s (%"PRIuLEAST64" packets recieved)", pkt_source_name(pkt_source), pkt_source->nb_packets);
            pkt_source_del(pkt_source);
            return NULL;
        } else if (nb_packets == 0) {
            if (pkt_source->is_file) {
                SLOG(LOG_INFO, "Stop sniffing from file %s (%"PRIuLEAST64" packets read)", pkt_source_name(pkt_source), pkt_source->nb_packets);
                pkt_source_del(pkt_source);
                return NULL;
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
            if (res != -2) {
                SLOG(LOG_ERR, "Cannot pcap_dispatch on pkt_source %s: %s", pkt_source_name(pkt_source), pcap_geterr(pkt_source->pcap_handle));
            }
            break;
        }
        assert(res == 1);   // 0 should not happen
        if (pkt_hdr->ts.tv_sec == 0) continue;   // should not happen, but does occur sometime (same goes for all other pcap header fields)
        if (! timeval_is_set(&file_start)) file_start = pkt_hdr->ts;
        sync_times(&file_start, &replay_start, &pkt_hdr->ts);
        if (terminating) break;
        callback((void *)pkt_source, pkt_hdr, packet);
    } while (1);

    SLOG(LOG_INFO, "Stop sniffing on packet source %s (%"PRIuLEAST64" packets recieved)", pkt_source_name(pkt_source), pkt_source->nb_packets);
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

static int pkt_source_ctor(struct pkt_source *pkt_source, char const *name, pcap_t *pcap_handle, void *(*sniffer)(void *), bool is_file, uint8_t dev_id)
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

    // FIXME: someone should care to pthread_join it at the end in order to release the few bytes storing the status (problem is the pkt_source is deleted in the spawned thread)
    if (0 != pthread_create(&pkt_source->sniffer, NULL, sniffer, pkt_source)) {
        SLOG(LOG_ERR, "Cannot start sniffer thread on pkt_source %s[?]@%p", pkt_source->name, pkt_source);  // Notice that pkt_source->instance is not inited yet
        LIST_REMOVE(pkt_source, entry);
        ret = -1;
        goto unlock_quit;
    }

unlock_quit:
    mutex_unlock(&pkt_sources_lock);
    return ret;
}

static struct pkt_source *pkt_source_new(char const *name, pcap_t *pcap_handle, void *(*sniffer)(void *), bool is_file, uint8_t dev_id)
{
    MALLOCER(pkt_source);
    struct pkt_source *pkt_source = mallocer_alloc(&mallocer_pkt_source, sizeof(*pkt_source));
    if (! pkt_source) return NULL;

    if (0 != pkt_source_ctor(pkt_source, name, pcap_handle, sniffer, is_file, dev_id)) {
        mallocer_free(pkt_source);
        pkt_source = NULL;
    }

    return pkt_source;
}

static struct pkt_source *pkt_source_new_file(char const *filename, char const *filter, bool rt)
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

    struct pkt_source *pkt_source = pkt_source_new(basename, handle, rt ? file_sniffer_rt:file_sniffer, true, pcap_id_seq++);
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

static struct pkt_source *pkt_source_new_if(char const *ifname, bool promisc, char const *filter, int buffer_size)
{
    char errbuf[PCAP_ERRBUF_SIZE] = "";

    SLOG(LOG_INFO, "Opening pcap device '%s'%s with filter %s and buffer size %d", ifname, promisc ? " in promiscuous mode":"", filter ? filter:"NONE", buffer_size);

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

    if (0 != pcap_set_snaplen(handle, 65535)) {
        SLOG(LOG_ALERT, "Cannot maximize snaplen for packet source %s: %s", ifname, pcap_geterr(handle));
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
    struct pkt_source *pkt_source = pkt_source_new(ifname, handle, iface_sniffer, false, dev_id);
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

    if (pkt_source->pcap_handle) pcap_close(pkt_source->pcap_handle);
}

static void pkt_source_del(struct pkt_source *pkt_source)
{
    pkt_source_dtor(pkt_source);
    mallocer_free(pkt_source);
    quit_if_nothing_opened();
}

// Caller must own pkt_sources_lock
static void pkt_source_terminate(struct pkt_source *pkt_source)
{
    SLOG(LOG_DEBUG, "Terminating packet source '%s'", pkt_source_name(pkt_source));
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
static SCM g_open_iface(SCM ifname_, SCM promisc_, SCM filter_, SCM buffer_size_)
{
    char *ifname = scm_to_tempstr(ifname_);
    bool const promisc = SCM_UNBNDP(promisc_) || scm_to_bool(promisc_);
    char const *filter = SCM_UNBNDP(filter_) ? NULL : scm_to_tempstr(filter_);
    int const buffer_size = SCM_UNBNDP(buffer_size_) ? 0 : scm_to_int(buffer_size_);

    struct pkt_source *pkt_source = pkt_source_new_if(ifname, promisc, filter, buffer_size);
    return pkt_source ? scm_from_locale_string(pkt_source_guile_name(pkt_source)) : SCM_UNSPECIFIED;
}

static struct ext_function sg_open_pcap;
static SCM g_open_pcap(SCM filename_, SCM rt_, SCM filter_)
{
    char const *filename = scm_to_tempstr(filename_);
    char const *filter = SCM_UNBNDP(filter_) ? NULL : scm_to_tempstr(filter_);
    bool const rt = SCM_UNBNDP(rt_) ? false : scm_to_bool(rt_);

    struct pkt_source *pkt_source = pkt_source_new_file(filename, filter, rt);
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

static struct ext_function sg_iface_stats;
static SCM g_iface_stats(SCM ifname_)
{
    mutex_lock(&pkt_sources_lock);
    struct pkt_source *pkt_source = pkt_source_of_scm(ifname_);
    SCM ret = SCM_UNSPECIFIED;

    if (! pkt_source) goto err;

    struct pcap_stat stats;
    bool have_stats = 0 == pcap_stats(pkt_source->pcap_handle, &stats);
    if (! have_stats) {
        SLOG(LOG_WARNING, "Cannot read stats for packet source %s: %s\n", pkt_source_name(pkt_source), pcap_geterr(pkt_source->pcap_handle));
    }

    ret = scm_list_n(
        scm_cons(scm_from_locale_symbol("id"),            scm_from_uint8(pkt_source->dev_id)),
        scm_cons(scm_from_locale_symbol("nb-packets"),    scm_from_uint64(pkt_source->nb_packets)),
        scm_cons(scm_from_locale_symbol("nb-duplicates"), scm_from_uint64(pkt_source->nb_duplicates)),
        scm_cons(scm_from_locale_symbol("tot-received"),  have_stats ? scm_from_uint(stats.ps_recv) : SCM_UNSPECIFIED),
        scm_cons(scm_from_locale_symbol("tot-dropped"),   have_stats ? scm_from_uint(stats.ps_drop) : SCM_UNSPECIFIED),
        scm_cons(scm_from_locale_symbol("nb-cap-bytes"),  scm_from_uint64(pkt_source->nb_cap_bytes)),
        scm_cons(scm_from_locale_symbol("nb-wire-bytes"), scm_from_uint64(pkt_source->nb_wire_bytes)),
        scm_cons(scm_from_locale_symbol("file?"),         scm_from_bool(pkt_source->is_file)),
        SCM_UNDEFINED);

err:
    mutex_unlock(&pkt_sources_lock);
    return ret;
}

static struct ext_function sg_dedup_stats;
static SCM g_dedup_stats(void)
{
    mutex_lock(&digest_stats_lock);
    SCM ret = scm_list_n(
        scm_cons(scm_from_locale_symbol("dup-found"),         scm_from_uint64(nb_dup_found)),
        scm_cons(scm_from_locale_symbol("nodup-found"),       scm_from_uint64(nb_nodup_found)),
        scm_cons(scm_from_locale_symbol("end-of-list-found"), scm_from_uint64(nb_eol_found)),
        scm_cons(scm_from_locale_symbol("searched-digests"),  scm_from_uint64(searched_digests)),
        SCM_UNDEFINED);
    mutex_unlock(&digest_stats_lock);

    return ret;
}

static struct ext_function sg_reset_dedup_stats;
static SCM g_reset_dedup_stats(void)
{
    reset_dedup_stats();
    return SCM_UNSPECIFIED;
}

// The first thing to do when quitting is to stop parsing traffic
void pkt_source_init(void)
{
    mutex_ctor(&cap_parser_lock, "parsers lock");
    mutex_ctor(&pkt_sources_lock, "pkt_sources");
    mutex_ctor(&digest_stats_lock, "digest_stats");
    EXT_LOCK(nb_digests);
    digests = digest_queue_new(nb_digests);
    if (! digests) nb_digests = 0;
    EXT_UNLOCK(nb_digests);

    ext_param_dup_detection_delay_init();
    ext_param_quit_when_done_init();
    ext_param_nb_digests_init();
    log_category_pkt_sources_init();

    ext_function_ctor(&sg_list_ifaces,
        "list-ifaces", 0, 0, 0, g_list_ifaces,
        "(list-ifaces): returns a list of all ifaces that can be opened for sniffing.\n"
        "Note that if you don't have sufficient permission to open a device then this device\n"
        "    will not appear in this list.\n"
        "See also (? 'open-iface) to start sniffing an interface.\n");

    ext_function_ctor(&sg_open_iface,
        "open-iface", 1, 3, 0, g_open_iface,
        "(open-iface \"iface-name\"): open the given iface, and set it in promiscuous mode.\n"
        "(open-iface \"iface-name\" #f): open the given iface without setting it\n"
        "    in promiscuous mode.\n"
        "(open-iface \"iface-name\" #t \"filter\"): open the given iface in promiscuous mode,\n"
        "    with the given packet filter.\n"
        "(open-iface \"iface-name\" #t \"[filter]\" (* 10 1024 1024)): open the given iface,\n"
        "    set it in promiscuous mode, apply the filter, and use a buffer size of 10Mb.\n"
        "Will return #t or #f depending on the success of the operation.\n"
        "See also (? 'list-ifaces) to have a list of all openable ifaces,\n"
        "    and (? 'close-iface) to close a given iface\n");

    ext_function_ctor(&sg_close_iface,
        "close-iface", 1, 0, 0, g_close_iface,
        "(close-iface \"iface-name\"): stop sniffing a previously opened iface.\n"
        "See also (? 'open-iface).\n");

    ext_function_ctor(&sg_open_pcap,
        "open-pcap", 1, 2, 0, g_open_pcap,
        "(open-pcap \"pcap-file\"): read the content of this pcap file, fullspeed.\n"
        "(open-pcap \"pcap-file\" #t): read this pcap file using its packet rate rather than fullspeed.\n"
        "(open-pcap \"pcap-file\" #f \"filter\"): same as above, applying given filter.\n"
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

    ext_function_ctor(&sg_dedup_stats,
        "deduplication-stats", 0, 0, 0, g_dedup_stats,
        "(deduplication-stats): return some statistics about the deduplication mechanism.\n"
        "See also (? 'reset-dedup-stats).\n");

    ext_function_ctor(&sg_reset_dedup_stats,
        "reset-deduplication-stats", 0, 0, 0, g_reset_dedup_stats,
        "(reset-deduplication-stats): does what the name suggest.\n"
        "You probably already know (? 'deduplication-stats).\n");
}

void pkt_source_fini(void)
{
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

    mutex_lock(&cap_parser_lock);
    if (cap_parser) cap_parser = parser_unref(cap_parser);
    mutex_dtor(&digest_stats_lock);
    mutex_unlock(&cap_parser_lock);
    mutex_dtor(&cap_parser_lock);
    mutex_dtor(&pkt_sources_lock);
    if (digests) {
        digest_queue_del(digests);
        digests = NULL;
    }

    log_category_pkt_sources_fini();
    ext_param_nb_digests_fini();
    ext_param_dup_detection_delay_fini();
    ext_param_quit_when_done_fini();
}
