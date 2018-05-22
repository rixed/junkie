// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2018, SecurActive.
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
#include <stdio.h>
#include "junkie/cpp.h"
#include "junkie/tools/cli.h"
#include "junkie/tools/objalloc.h"
#include "junkie/tools/tempstr.h"
#include "junkie/tools/hash.h"
#include "junkie/tools/ip_addr.h"
#include "junkie/tools/term.h"
#include "junkie/proto/ip.h"
#include "junkie/proto/tls.h"

static bool display_help;
static int64_t refresh_rate = 1000000;  // 1 sec

/* Keep an hash of certificate serial number to subject + issuer + validity +
 * set of all IP using it + number of uses. */

struct cert {
    HASH_ENTRY(cert) entry;  // All certs by serial number
    TAILQ_ENTRY(cert) top_entry; // Top cert
    // For the key we build the string representation of the serial number,
    // cleared with 0s at the end.
#   define MAX_KEY_SIZE (20*2 + 1)
    char key[MAX_KEY_SIZE];
    struct tls_cert_info info;
    // TODO: a hash?
    unsigned nb_servers;
    struct ip_addr servers[100];
    unsigned count;
};

static struct mutex certs_lock;

static HASH_TABLE(certs, cert) certs;

static void key_ctor(char *key, struct tls_cert_info const *info)
{
    for (unsigned d = 0; d < MAX_KEY_SIZE; d ++) {
        if (d/2 >= info->serial_number.len) {
            key[d] = '\0';
        } else {
            uint8_t byte = info->serial_number.num[d/2];
            uint8_t digit = (d & 1 ? byte : (byte >> 4)) & 0xf;
            key[d] = digit < 10 ? '0' + digit : 'A' + (digit - 10);
        }
    }
}

// We then order the first N cert according to some ordering function.

// Such as these ones:
static int cmp_not_after(struct cert const *c1, struct cert const *c2)
{
    return cmp_ber_time(&c1->info.not_after, &c2->info.not_after);
}
static int cmp_not_before(struct cert const *c1, struct cert const *c2)
{
    return cmp_ber_time(&c1->info.not_before, &c2->info.not_before);
}
static int cmp_issuer(struct cert const *c1, struct cert const *c2)
{
    return strcmp(c1->info.issuer, c2->info.issuer);
}
static int cmp_subject(struct cert const *c1, struct cert const *c2)
{
    return strcmp(c1->info.subject, c2->info.subject);
}
static int cmp_count(struct cert const *c1, struct cert const *c2)
{
    if (c1->count < c2->count) return -1;
    else if (c1->count == c2->count) return 0;
    else return 1;
}

static struct sort_key {
    char key;
    char const *title;
    int (*cmp)(struct cert const *, struct cert const *);
} sort_keys[] = {
    { .key = 'a', .title = "not-after (default)", .cmp = cmp_not_after },
    { .key = 'b', .title = "not-before", .cmp = cmp_not_before },
    { .key = 'i', .title = "issuer", .cmp = cmp_issuer },
    { .key = 's', .title = "subject", .cmp = cmp_subject },
    { .key = 'c', .title = "count", .cmp = cmp_count }
};

static struct sort_key const *sort_key = sort_keys + 0;

#define MAX_TOP 1000
static unsigned top_n = MAX_TOP;    // how many entries we want (ie. NB_LINES)
static unsigned top_len = 0;      // how many certs we actually have in the top
static TAILQ_HEAD(certs_tailq, cert) top = TAILQ_HEAD_INITIALIZER(top);

static void top_insert(struct cert *new, int (*cmp)(struct cert const *, struct cert const *))
{
    struct cert *cert;
    TAILQ_FOREACH(cert, &top, top_entry) {
        if (cmp(new, cert) <= 0) break;
    }
    if (cert == NULL) { // insert at the end
        TAILQ_INSERT_TAIL(&top, new, top_entry);
    } else {
        TAILQ_INSERT_BEFORE(cert, new, top_entry);
    }
}

static void top_maybe_insert(struct cert *new, int (*cmp)(struct cert const *, struct cert const *))
{
    if (top_len < top_n) {
        top_insert(new, cmp);
        top_len ++;
    } else {
        struct cert const *last_cert = TAILQ_LAST(&top, certs_tailq);
        if (cmp(new, last_cert) < 0) {
            TAILQ_REMOVE(&top, last_cert, top_entry);
            top_insert(new, sort_key->cmp);
        }
    }
}

static void top_empty(void)
{
    while (!TAILQ_EMPTY(&top))
        TAILQ_REMOVE(&top, TAILQ_FIRST(&top), top_entry);
    top_len = 0;
}

static void top_insert_all(int (*cmp)(struct cert const *, struct cert const *))
{
    struct cert *cert;
    HASH_FOREACH(cert, &certs, entry) {
        top_maybe_insert(cert, cmp);
    }
}

static void top_rebuild(int (*cmp)(struct cert const *, struct cert const *))
{
    mutex_lock(&certs_lock);
    top_empty();
    top_insert_all(cmp);
    mutex_unlock(&certs_lock);
}

struct column {
    char const *title;
    unsigned width;
    char *text[MAX_TOP];
};

static void column_set_data(struct column *col, unsigned lineno, char const *str)
{
    assert(lineno < MAX_TOP);
    size_t len = strlen(str);
    if (len > col->width) col->width = len;
    col->text[lineno] = strdup(str);
}

static void column_set_data_uint(struct column *col, unsigned lineno, unsigned n)
{
    assert(lineno < MAX_TOP);
#   define MAX_INT_STR 16
    col->text[lineno] = malloc(MAX_INT_STR);
    assert(col->text[lineno]);
    if (snprintf(col->text[lineno], sizeof(MAX_INT_STR), "%u", n) > MAX_INT_STR)
        assert(!"too large int");
    size_t len = strlen(col->text[lineno]);
    if (len > col->width) col->width = len;
}

static void column_ctor(struct column *col, char const *title)
{
    col->title = title;
    col->width = strlen(title);
    for (unsigned l = 0; l < NB_ELEMS(col->text); l++) col->text[l] = NULL;
}

static void column_dtor(struct column *col)
{
    for (unsigned l = 0; l < NB_ELEMS(col->text); l++) {
        if (col->text[l]) {
            free(col->text[l]);
            col->text[l] = NULL;
        }
    }
}

static void table_dtor(struct column *col, unsigned nb_cols)
{
    for (unsigned c = 0; c < nb_cols; c++)
        column_dtor(col+c);
}

static void table_display(struct column *columns, unsigned nb_cols, unsigned nb_lines, unsigned max_width)
{
    unsigned tot_width = 0;
    for (unsigned c = 0; c < nb_cols; c++) {
        tot_width += columns[c].width + (c < nb_cols-1 ? 1:0);
    }
#   define SEQNUM 0
#   define SUBJECT 1
#   define ISSUER 2
    int extra = (int)tot_width - max_width;
    unsigned trunc_subject = extra > 0 ? MIN(extra / 2U, columns[SUBJECT].width) : 0;
    unsigned trunc_issuer = extra > 0 ? MIN(extra - trunc_subject, columns[ISSUER].width) : 0;
    unsigned trunc_seqnum = extra > 0 ? MIN(extra - trunc_subject - trunc_issuer, columns[SEQNUM].width) : 0;

    printf(REVERSE);
    for (unsigned c = 0; c < nb_cols; c++) {
        int w = columns[c].width;
        if (c == SUBJECT) w -= trunc_subject;
        else if (c == ISSUER) w -= trunc_issuer;
        else if (c == SEQNUM) w -= trunc_seqnum;
        assert(w >= 0 && w < 1000);
        printf("%*.*s%s", w, w, columns[c].title, c < nb_cols-1 ? "|":"");
    }
    printf(NORMAL "\n");

    for (unsigned l = 0; l < nb_lines; l++) {
        for (unsigned c = 0; c < nb_cols; c++) {
            int w = columns[c].width;
            if (c == SUBJECT) w -= trunc_subject;
            else if (c == ISSUER) w -= trunc_issuer;
            else if (c == SEQNUM) w -= trunc_seqnum;
            assert(w >= 0 && w < 1000);
            printf("%*.*s%s", w, w, columns[c].text[l], c < nb_cols-1 ? REVERSE"|"NORMAL:"");
        }
        printf("\n");
    }
}

static void do_display_top(struct timeval const unused_ *now)
{
    unsigned nb_lines, max_width;
    get_window_size(&max_width, &nb_lines);
    if (nb_lines < 5) nb_lines = MAX_TOP;  // probably get_window_size failed?
    top_n = MIN(MAX_TOP, nb_lines - 2);

    struct column columns[6];
    column_ctor(columns + 0, "Serial Number");
    column_ctor(columns + 1, "Subject");
    column_ctor(columns + 2, "Issuer");
    column_ctor(columns + 3, "Not Before");
    column_ctor(columns + 4, "Not After");
    column_ctor(columns + 5, "Count");

    printf(TOPLEFT CLEAR);
    mutex_lock(&certs_lock);
    struct cert *cert;
    unsigned lineno = 0;
    TAILQ_FOREACH(cert, &top, top_entry) {
        column_set_data(columns+0, lineno, ber_uint_2_str(&cert->info.serial_number));
        column_set_data(columns+1, lineno, cert->info.subject);
        column_set_data(columns+2, lineno, cert->info.issuer);
        column_set_data(columns+3, lineno, ber_time_2_str(&cert->info.not_before));
        column_set_data(columns+4, lineno, ber_time_2_str(&cert->info.not_after));
        column_set_data_uint(columns+5, lineno, cert->count);
        if (++lineno > top_n) break;
    }
    mutex_unlock(&certs_lock);

    table_display(columns, NB_ELEMS(columns), lineno, max_width);
    table_dtor(columns, NB_ELEMS(columns));
}

static struct timeval last_display;

static void try_display(struct timeval const *now)
{
    if (timeval_is_set(&last_display) && timeval_sub(now, &last_display) < refresh_rate) return;
    last_display = *now;

    do_display_top(now);
}

static void tls_callback(struct proto_subscriber unused_ *subscription, struct proto_info const *last, size_t unused_ tot_cap_len, uint8_t const unused_ *tot_packet, struct timeval const *now)
{
    ASSIGN_INFO_CHK(tls, last, );
    // Do we have a certificate?
    if (! (tls->set_values & NB_CERTS_SET)) return;
    if (tls->u.handshake.nb_certs == 0) return;
    ASSIGN_INFO_CHK2(ip, ip6, &tls->info, );
    ip = ip ? ip:ip6;

    for (unsigned c = 0; c < tls->u.handshake.nb_certs; c++) {
        char key[MAX_KEY_SIZE];
        key_ctor(key, tls->u.handshake.certs + c);
        struct cert *cert;
        mutex_lock(&certs_lock);
        HASH_LOOKUP(cert, &certs, &key, key, entry);
        if (cert) {
            SLOG(LOG_DEBUG, "SN %s already known", key);
            // TODO: check it's actually the same cert
            cert->count ++;
            // TODO: add IP
        } else {
            cert = objalloc(sizeof(*cert), "certs");
            if (! cert) return;
            ASSERT_COMPILE(sizeof(cert->key == key));
            memcpy(cert->key, key, sizeof(key));
            cert->info = tls->u.handshake.certs[c];
            cert->count= 1;
            cert->nb_servers = 0; // TODO
            SLOG(LOG_INFO, "New cert: %s\n", tls_cert_info_2_str(tls->u.handshake.certs+c, c));
            HASH_INSERT(&certs, cert, &cert->key, entry);
            top_maybe_insert(cert, sort_key->cmp);
        }
        mutex_unlock(&certs_lock);
    }

    if (! display_help) try_display(now);
}

static void do_display_help(void)
{
    printf(
        TOPLEFT CLEAR
        BRIGHT "Help for Interactive Commands" NORMAL " - SSLogramv%s\n"
        "\n", version_string);
    printf(
        "Certificates are sorted according to: " BRIGHT "%s" NORMAL "\n"
        "Refresh rate is: " BRIGHT "%.2fs" NORMAL "\n"
        "\n"
        "  " BRIGHT "+/-" NORMAL "   Refresh rate twice faster/slower\n"
        "  " BRIGHT "h,H,?" NORMAL " this help screen\n"
        "  " BRIGHT "q" NORMAL "     return to main screen\n"
        "  " BRIGHT "q,^C" NORMAL "  quit\n",
        sort_key->title,
        refresh_rate/1000000.);
    for (unsigned u = 0; u < NB_ELEMS(sort_keys); u++) {
        printf("  " BRIGHT "%c" NORMAL "     sort by %s\n",
               sort_keys[u].key, sort_keys[u].title);
    }
}

// Key handling function
static void handle_key(char c)
{
    switch (c) {
        case '+': refresh_rate *= 2; break;
        case '-': refresh_rate = MAX(refresh_rate/2, 1000); break;
        case '?':
        case 'h':
        case 'H': display_help ^= 1; break;
        case 'q':
            if (display_help) {
                display_help = false;
            } else {
                term_fini();
                _exit(0);
            }
        case '\n':
            if (display_help) {
                display_help = false;
            }
            break;
        default:
            for (unsigned u = 0; u < NB_ELEMS(sort_keys); u++) {
                if (sort_keys[u].key == c) {
                    if (sort_key != sort_keys + u) {
                        sort_key = sort_keys + u;
                        top_rebuild(sort_key->cmp);
                    }
                    break;
                }
            }
            break;
    }
    // Refresh help page after each keystroke
    if (display_help) do_display_help();
    else do_display_top(&last_display);
}

static struct proto_subscriber subscription;

void on_load(void)
{
    term_init(&handle_key);
    objalloc_init();
    hash_init();
    SLOG(LOG_INFO, "Loading sslogram");
    HASH_INIT(&certs, 103, "x509 certificates");
    mutex_ctor(&certs_lock, "sslogram lock");
    hook_subscriber_ctor(&proto_tls->hook, &subscription, tls_callback);
}

void on_unload(void)
{
    SLOG(LOG_INFO, "Unloading sslogram");
    term_fini();
    hook_subscriber_dtor(&proto_tls->hook, &subscription);
    HASH_DEINIT(&certs);
    // Keep the lock alive as another thread might still call us back
    hash_fini();
    objalloc_fini();
}
