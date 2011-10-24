// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#undef NDEBUG
#include <assert.h>
#include <junkie/tools/log.h>
#include <junkie/tools/miscmacs.h>
#include <junkie/tools/ext.h>
#include "proto/streambuf.c"

static char *payloads[] = {
    "Maitre corbeau, sur un arbre perche,",
    "tenait en son bec un fromage.",
    "Maitre renard, par l'odeur alleche",
    "lui tint a peut pres ce langage :",
};

static struct streambuf sbuf;
static unsigned nb_calls = 0;
static unsigned nb_chunks = 0;

enum proto_parse_status parse(struct parser *parser, struct proto_info unused_ *info, unsigned way, uint8_t const *packet, size_t cap_len, size_t unused_ wire_len, struct timeval const unused_ *now, size_t unused_ tot_cap_len, uint8_t const unused_ *tot_packet)
{
    struct streambuf *sbuf = (struct streambuf *)parser;

    assert(cap_len > 0);
    SLOG(LOG_DEBUG, "Parse called on payload '%.*s'", (int)cap_len, packet);
    assert(packet[0] >= 'A' && packet[0] <= 'Z');   // Since we ask for the sentences to be given in full.

    nb_calls ++;
    int last_punct = -1;

    // wait for a '.' or a ':' before proceeding :
    for (unsigned l = 0; l < cap_len; l++) {
        if (packet[l] == '.' || packet[l] == ':') {
            nb_chunks ++;
            last_punct = l;
        }
    }

    // we are probably in the middle of a chunk. Remember up to last_punct seen
    streambuf_set_restart(sbuf, way, packet + (last_punct+1), true);

    return PROTO_OK;
}

static void setup(void)
{
    nb_calls = 0;
    nb_chunks = 0;
    assert(0 == streambuf_ctor(&sbuf, parse, 80));
}

static void teardown(void)
{
    streambuf_dtor(&sbuf);
}

// Check that we get all the payload we asked for, once
static void check_simple(void)
{
    setup();

    for (unsigned p = 0; p < NB_ELEMS(payloads); p++) {
        size_t len = strlen(payloads[p]);
        enum proto_parse_status status = streambuf_add(&sbuf, (struct parser *)&sbuf, NULL, 0, (uint8_t *)payloads[p], len, len, NULL, len, (uint8_t *)payloads[p]);   // in actual situations the streambuf will be a member of the overloaded parser
        assert(status == PROTO_OK);
    }

    assert(nb_calls == NB_ELEMS(payloads));
    assert(nb_chunks == 2);

    teardown();
}

// Same as above, sending bytes per bytes
static void check_vicious(void)
{
    setup();

    for (unsigned p = 0; p < NB_ELEMS(payloads); p++) {
        size_t len = strlen(payloads[p]);
        for (unsigned c = 0; c < len; c++) {
            enum proto_parse_status status = streambuf_add(&sbuf, (struct parser *)&sbuf, NULL, 0, (uint8_t *)(payloads[p]+c), 1, 1, NULL, 1, (uint8_t *)(payloads[p]+c));
            assert(status == PROTO_OK);
        }
    }

    assert(nb_chunks == 2);

    teardown();
}

// Now we check that we do not buffer more than 80 bytes (see streambuf_ctor)
static void check_drop(void)
{
    setup();
    static char payload[] = "This is a very long sentence without much ponctiation so that the parser will not receive it since its buffering would exceed the eighty allowed characters.";
    int len = strlen(payload);
    assert(len > 80);

    enum proto_parse_status status;
    status = streambuf_add(&sbuf, (struct parser *)&sbuf, NULL, 0, (uint8_t *)"A", 1, 1, NULL, 1, (uint8_t *)"A");   // A first packet for triggering the buffering
    assert(status == PROTO_OK);
    status = streambuf_add(&sbuf, (struct parser *)&sbuf, NULL, 0, (uint8_t *)payload, len, len, NULL, len, (uint8_t *)payload);   // then a long one
    assert(status == PROTO_PARSE_ERR);

    teardown();
}

int main(void)
{
    log_init();
    ext_init();
    objalloc_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("streambuf_check.log");

    check_simple();
    check_vicious();
    check_drop();

    objalloc_fini();
    ext_fini();
    log_fini();
    return EXIT_SUCCESS;
}

