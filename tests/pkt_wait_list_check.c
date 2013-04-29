// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <time.h>
#include <junkie/tools/miscmacs.h>
#include <junkie/tools/ext.h>
#include <junkie/tools/objalloc.h>
#include "pkt_wait_list.c"

#undef LOG_CAT
#define LOG_CAT global_log_category

/*
 * Check that we do not leak memory nor destroy anything by creating and destructing a pkt_wait_list
 */

static void ctor_dtor_check(void)
{
    struct pkt_wl_config config;
    pkt_wl_config_ctor(&config, "test1", 0, 0, 0, 0);

    struct parser *dummy = proto_dummy->ops->parser_new(proto_dummy);
    assert(dummy);
    struct pkt_wait_list wl;

    assert(0 == pkt_wait_list_ctor(&wl, 10, &config, dummy, NULL));
    pkt_wait_list_dtor(&wl);

    parser_unref(&dummy);
    pkt_wl_config_dtor(&config);
}

/*
 * Check that the parse function of a parser receives everything once
 */

static struct uniq_proto test_proto;
static struct parser *test_parser;
static struct timeval now;
static struct pkt_wait_list wl;
static unsigned next_msg;
static struct pkt_wl_config config;

static enum proto_parse_status test_parse(struct parser *parser, struct proto_info unused_ *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    SLOG(LOG_DEBUG, "got payload '%.*s'", (int)cap_len, packet);
    assert(parser == test_parser);
    assert(cap_len == wire_len);
    assert(cap_len > 0);
    unsigned seqnum = packet[0] - '0';
    assert(seqnum == next_msg);
    assert(packet[cap_len-1] == '\0');
    next_msg ++;
    return proto_parse(NULL, NULL, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
}

static void wl_check_setup(void)
{
    pkt_wl_config_ctor(&config, "test", 1000, 0, 0, 0);

    static struct proto_ops const ops = {
        .parse      = test_parse,
        .parser_new = uniq_parser_new,
        .parser_del = uniq_parser_del,
    };
    uniq_proto_ctor(&test_proto, &ops, "Test", PROTO_CODE_DUMMY);

    test_parser = test_proto.proto.ops->parser_new(&test_proto.proto);
    assert(test_parser);

    assert(0 == pkt_wait_list_ctor(&wl, 0, &config, test_parser, NULL));

    next_msg = 0;

    return;
}

static void wl_check_teardown(void)
{
    parser_unref(&test_parser);
    uniq_proto_dtor(&test_proto);
    pkt_wl_config_dtor(&config);
}

// Simple case : when packets are receiving in the right order we call the parser function at once and nothing gets stored on the wl ever
static void simple_check(void)
{
    wl_check_setup();
    char *packets[] = {
        "0. Deux mulets cheminaient, l'un d'avoine chargé,",
        "1. L'autre portant l'argent de la gabelle",
        "2. Celui-ci, glorieux d'une charge si belle,",
        "3. N'eût voulu pour beaucoup en être soulagé."
    };
    unsigned offset = 0;
    for (unsigned p = 0; p < NB_ELEMS(packets); p++) {
        assert(wl.next_offset == offset);
        int len = strlen(packets[p]) + 1;
        assert(PROTO_OK == pkt_wait_list_add(&wl, offset, offset+len, false, 0, true, NULL, 0, (uint8_t *)packets[p], len, len, &now, len, (uint8_t *)packets[p]));
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
        "0. Un astrologue un jour se laissa choir",
        "1. Au fond d'un puits. On lui dit : \" Pauvre bête,",
        "2. Tandis qu'à peine à tes pieds tu peux voir,",
        "3. Penses-tu lire au-dessus de ta tête ? \""
    };
    unsigned order[NB_ELEMS(packets)] = { 2, 1, 3, 0 };
    for (unsigned o = 0; o < NB_ELEMS(order); o++) {
        unsigned const p = order[o];
        unsigned offset = 0;
        for (unsigned pp = 0; pp < p; pp++) offset += strlen(packets[pp]) + 1;
        int len = strlen(packets[p]) + 1;
        assert(PROTO_OK == pkt_wait_list_add(&wl, offset, offset+len, false, 0, true, NULL, 0, (uint8_t *)packets[p], len, len, &now, len, (uint8_t *)packets[p]));
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

    assert(PROTO_OK == pkt_wait_list_add(&wl, 999998, 999999, false, 0, true, NULL, 0, (uint8_t *)"X", 1, 1, &now, 1, (uint8_t *)"X"));
    assert(PROTO_OK == pkt_wait_list_add(&wl, 999997, 999998, false, 0, true, NULL, 0, (uint8_t *)"X", 1, 1, &now, 1, (uint8_t *)"X"));
    char packet[] = "0. Maitre corbeau sur un arbre perche tenait en son bec un fromage";
    int const len = strlen(packet) + 1;
    assert(PROTO_OK == pkt_wait_list_add(&wl, 0, 0+len, false, 0, true, NULL, 0, (uint8_t *)packet, len, len, &now, len, (uint8_t *)packet));
    assert(LIST_EMPTY(&wl.pkts));
    assert(next_msg == 1);

    wl_check_teardown();
}

/*
 * Reassembly checks
 */

static char msg[] =
    "Pendant qu'un philosophe assure\n"
    "Que toujours par leurs sens les hommes sont dupés,\n"
    "       Un autre philosophe jure\n"
    "       Qu'ils ne nous ont jamais trompés.\n"
    "Tous les deux ont raison; et la philosophie\n"
    "Dit vrai, quand elle dit que les sens tromperont,\n"
    "Mais que sur leur rapport les hommes jugeront;\n"
    "       Mais aussi, si l'on rectifie\n"
    "L'image de l'objet sur son éloignement,\n"
    "       Sur le milieu qui l'environne,\n"
    "       Sur l'organe et sur l'instrument,\n"
    "       Les sens ne tromperont personne.\n";

static bool sent_mask[NB_ELEMS(msg)] = { false, };
static unsigned prev_unsent;

static bool all_sent(void)
{
    for (unsigned c = prev_unsent; c < NB_ELEMS(sent_mask); c++) {
        if (! sent_mask[c]) {
            prev_unsent = c;
            return false;
        }
    }
    return true;
}

static void mark_sent(unsigned start, unsigned len)
{
    while (len--) sent_mask[start+len] = true;
}

static void reset_sent(void)
{
    prev_unsent = 0;
    for (unsigned c = 0; c < NB_ELEMS(sent_mask); c++) {
        sent_mask[c] = false;
    }
}

static void reassembly_check(void)
{
    wl_check_setup();
    reset_sent();

    // We sent the message one random piece at a time, using less pieces thant the wait_list defined limit.
    unsigned nb_pieces = 0;
    while (! all_sent()) {
        unsigned start, len;
        if (nb_pieces < 900) {
            start = rand() % NB_ELEMS(msg);
            len = rand() % 16;
        } else {    // sent everything!
            SLOG(LOG_WARNING, "Too many small pieces, must send everything now!");
            start = 0;
            len = NB_ELEMS(msg);
        }
        unsigned const len_ = MIN(len, NB_ELEMS(msg)-start);
        assert(PROTO_OK == pkt_wait_list_add(&wl, start, start+len_, false, 0, false, NULL, 0, (uint8_t *)msg+start, len_, len_, &now, len_, (uint8_t *)msg+start));
        mark_sent(start, len_);
        if (len != len_) {
            len -= len_;
            assert(PROTO_OK == pkt_wait_list_add(&wl, 0, len, false, 0, false, NULL, 0, (uint8_t *)msg, len, len, &now, len, (uint8_t *)msg));
            mark_sent(0, len);
        }

        nb_pieces ++;
    }

    // Now that we sent everyhting try reassembling :
    uint8_t *msg2 = pkt_wait_list_reassemble(&wl, 0, NB_ELEMS(msg));
    assert(msg2);
    assert(0 == memcmp(msg, msg2, NB_ELEMS(msg)));
}

/*
 * Startup
 */

int main(void)
{
    log_init();
    ext_init();
    objalloc_init();
    proto_init();
    pkt_wait_list_init();
    ref_init();
    srand(time(NULL));
    log_set_level(LOG_INFO, NULL);  // DEBUG make the test too slow
    log_set_file("pkt_wait_list_check.log");

    ctor_dtor_check();
    simple_check();
    reorder_check();
    gap_check();
    for (unsigned t = 0; t < 1000; t++) {
        reassembly_check();
    }

    doomer_stop();
    ref_fini();
    pkt_wait_list_fini();
    proto_fini();
    objalloc_fini();
    ext_fini();
    log_fini();
    return EXIT_SUCCESS;
}

void fuzz(struct parser unused_ *parser, uint8_t const unused_ *packet, size_t unused_ packet_len, unsigned unused_ max_nb_fuzzed_bits)
{
}
