// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <junkie/tools/miscmacs.h>
#include "pkt_wait_list.c"

/*
 * Check offset_compare()
 */

static void offset_compare_check(void)
{
    assert(offset_compare(0, 0, 0, 0) == 0);
    assert(offset_compare(42, 42, 42, 42) == 0);
    assert(offset_compare(10, 0, 9, 0) == 1);
    assert(offset_compare(9, 0, 10, 0) == -1);
}

/*
 * Check that we do not leak memory nor destroy anything by creating and destructing a pkt_wait_list
 */

static void ctor_dtor_check(void)
{
    struct timeval now;
    timeval_set_now(&now);
    struct parser *dummy = proto_dummy->ops->parser_new(proto_dummy, &now);
    assert(dummy);
    struct pkt_wait_list wl;

    assert(0 == pkt_wait_list_ctor(&wl, 10, 0, 0, 0, 0, dummy));
    pkt_wait_list_dtor(&wl, &now);

    parser_unref(dummy);
}

/*
 * Check that the parse function of a parser receives everything once
 */

static struct uniq_proto test_proto;
static struct parser *test_parser;
static struct timeval now;
static struct pkt_wait_list wl;
static unsigned next_msg;

static enum proto_parse_status test_parse(struct parser *parser, struct proto_info unused_ *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn)
{
    SLOG(LOG_DEBUG, "got payload '%.*s'", (int)cap_len, packet);
    assert(parser == test_parser);
    assert(cap_len == wire_len);
    assert(cap_len > 0);
    unsigned seqnum = packet[0] - '0';
    assert(seqnum == next_msg);
    assert(packet[cap_len-1] == '\0');
    next_msg ++;
    return proto_parse(NULL, NULL, way, NULL, 0, 0, now, okfn);
}

static void wl_check_setup(void)
{
    static struct proto_ops const ops = {
        .parse      = test_parse,
        .parser_new = uniq_parser_new,
        .parser_del = uniq_parser_del,
    };
    uniq_proto_ctor(&test_proto, &ops, "Test");

    timeval_set_now(&now);

    test_parser = test_proto.proto.ops->parser_new(&test_proto.proto, &now);
    assert(test_parser);

    assert(0 == pkt_wait_list_ctor(&wl, 0, 0, 1000, 0, 0, test_parser));

    next_msg = 0;

    return;
}

static void wl_check_teardown(void)
{
    parser_unref(test_parser);
    uniq_proto_dtor(&test_proto);
}

// Simple case : when packets are receiving in the right order we call the parser function at once and nothing gets stored on the wl ever
static void simple_check(void)
{
    wl_check_setup();
    char *packets[] = {
        "0. une poule sur un mur",
        "1. qui picore du pain dur",
        "2. picoti, picota,",
        "3. leve la queue et puis s'en va."
    };
    unsigned offset = 0;
    for (unsigned p = 0; p < NB_ELEMS(packets); p++) {
        assert(wl.next_offset == offset);
        int len = strlen(packets[p]) + 1;
        assert(PROTO_OK == pkt_wait_list_add(&wl, offset, offset+len, true, NULL, 0, (uint8_t *)packets[p], len, len, &now, NULL));
        offset += len;
        assert(LIST_EMPTY(&wl.pkts));
    }

    // Check we parsed everything
    assert(next_msg == 4);

    wl_check_teardown();
}

// Now we send every packets out of order and check that the parse function receives them in correct order
static void reorder_check(void)
{
    wl_check_setup();
    char *packets[] = {
        "0. Vive le vent, vive le vent,",
        "1. vive le vendalisme !",
        "2. Faut peter toutes les vitrines",
        "3. avec nos barres a mines !"
    };
    unsigned order[NB_ELEMS(packets)] = { 2, 1, 3, 0 };
    for (unsigned o = 0; o < NB_ELEMS(order); o++) {
        unsigned const p = order[o];
        unsigned offset = 0;
        for (unsigned pp = 0; pp < p; pp++) offset += strlen(packets[pp]) + 1;
        int len = strlen(packets[p]) + 1;
        assert(PROTO_OK == pkt_wait_list_add(&wl, offset, offset+len, true, NULL, 0, (uint8_t *)packets[p], len, len, &now, NULL));
    }
 
    // Check we parsed everything
    assert(LIST_EMPTY(&wl.pkts));
    assert(next_msg == 4);

    wl_check_teardown();
}

// Check that our test_parser receives only legitimate offsets
static void gap_check(void)
{
    wl_check_setup();

    assert(PROTO_OK == pkt_wait_list_add(&wl, 999998, 999999, true, NULL, 0, (uint8_t *)"X", 1, 1, &now, NULL));
    assert(PROTO_OK == pkt_wait_list_add(&wl, 999997, 999998, true, NULL, 0, (uint8_t *)"X", 1, 1, &now, NULL));
    char packet[] = "0. Maitre corbeau sur un arbre perche tenait en son bec un fromage";
    int const len = strlen(packet) + 1;
    assert(PROTO_OK == pkt_wait_list_add(&wl, 0, 0+len, true, NULL, 0, (uint8_t *)packet, len, len, &now, NULL));
    assert(LIST_EMPTY(&wl.pkts));
    assert(next_msg == 1);

    wl_check_teardown();
}

/*
 * Startup
 */

int main(void)
{
    log_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("pkt_wait_list_check.log");
    proto_init();

    offset_compare_check();
    ctor_dtor_check();
    simple_check();
    reorder_check();
    gap_check();

    proto_fini();
    log_fini();
    return EXIT_SUCCESS;
}

void fuzz(struct parser unused_ *parser, uint8_t const unused_ *packet, size_t unused_ packet_len, unsigned unused_ max_nb_fuzzed_bits)
{
}
