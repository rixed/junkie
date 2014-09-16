// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#undef NDEBUG
#include <assert.h>
#include <junkie/tools/log.h>
#include <junkie/tools/miscmacs.h>
#include <junkie/tools/ext.h>
#include "lib_test_junkie.h"
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

static enum proto_parse_status parse(struct parser *parser, struct proto_info unused_ *info,
        unsigned way, uint8_t const *packet, size_t cap_len, size_t unused_ wire_len,
        struct timeval const unused_ *now, size_t unused_ tot_cap_len, uint8_t const unused_ *tot_packet)
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
    streambuf_set_restart(sbuf, way, packet + (last_punct+1), 1);

    return PROTO_OK;
}

static void setup(parse_fun fun)
{
    nb_calls = 0;
    nb_chunks = 0;
    assert(0 == streambuf_ctor(&sbuf, fun, 80, NULL));
}

static void teardown(void)
{
    streambuf_dtor(&sbuf);
}

struct timeval now;

// Check that we get all the payload we asked for, once
static int check_simple(void)
{
    for (unsigned p = 0; p < NB_ELEMS(payloads); p++) {
        size_t len = strlen(payloads[p]);
        enum proto_parse_status status = streambuf_add(&sbuf, (struct parser *)&sbuf, NULL, 0,
                (uint8_t *)payloads[p], len, len, &now, len, (uint8_t *)payloads[p]);   // in actual situations the streambuf will be a member of the overloaded parser
        assert(status == PROTO_OK);
    }

    CHECK_INT(nb_calls, NB_ELEMS(payloads));
    CHECK_INT(nb_chunks, 2);

    return 0;
}

// Same as above, sending bytes per bytes
static int check_vicious(void)
{
    for (unsigned p = 0; p < NB_ELEMS(payloads); p++) {
        size_t len = strlen(payloads[p]);
        for (unsigned c = 0; c < len; c++) {
            enum proto_parse_status status = streambuf_add(&sbuf, (struct parser *)&sbuf, NULL, 0, (uint8_t *)(payloads[p]+c), 1, 1, &now, 1, (uint8_t *)(payloads[p]+c));
            assert(status == PROTO_OK);
        }
    }
    CHECK_INT(nb_chunks, 2);
    return 0;
}

static char long_payload[] = "This is a very long sentence without much ponctiation so that the parser will not receive it since its buffering would exceed the eighty allowed characters.";
static size_t len_payload = 156;

// Now we check that we do not buffer more than 80 bytes (see streambuf_ctor)
static int check_drop(void)
{
    assert(len_payload > 80);
    struct streambuf_unidir *dir = sbuf.dir + 0;
    enum proto_parse_status status;

    status = streambuf_add(&sbuf, (struct parser *)&sbuf, NULL, 0, (uint8_t *)"A", 1, 1,
            &now, 1, (uint8_t *)"A");   // A first packet for triggering the buffering
    CHECK_INT(status, PROTO_OK);
    CHECK_INT(dir->cap_len, 1);
    CHECK_INT(dir->wire_len, 1);

    status = streambuf_add(&sbuf, (struct parser *)&sbuf, NULL, 0, (uint8_t *)long_payload,
            len_payload, len_payload, &now, len_payload, (uint8_t *)long_payload);   // then a long one
    CHECK_INT(status, PROTO_OK);
    CHECK_INT(dir->cap_len, 80);
    CHECK_INT(dir->wire_len, len_payload + 1);

    status = streambuf_add(&sbuf, (struct parser *)&sbuf, NULL, 0, (uint8_t *)long_payload,
            len_payload, len_payload, &now, len_payload, (uint8_t *)long_payload);   // another long one
    CHECK_INT(status, PROTO_OK);
    CHECK_INT(dir->cap_len, 80);
    CHECK_INT(dir->wire_len, len_payload * 2 + 1);

    streambuf_set_restart(&sbuf, 0, dir->buffer + 1, 1);
    status = streambuf_add(&sbuf, (struct parser *)&sbuf, NULL, 0, (uint8_t *)long_payload,
            len_payload, len_payload, &now, len_payload, (uint8_t *)long_payload);   // this time, advance buffer
    CHECK_INT(status, PROTO_OK);
    CHECK_INT(dir->cap_len, 79);
    CHECK_INT(dir->wire_len, len_payload * 3);

    streambuf_set_restart(&sbuf, 0, dir->buffer + len_payload * 3, 1);
    status = streambuf_add(&sbuf, (struct parser *)&sbuf, NULL, 0, (uint8_t *)long_payload,
            len_payload, len_payload, &now, len_payload, (uint8_t *)long_payload);   // this time, really advance buffer
    CHECK_INT(status, PROTO_OK);
    CHECK_INT(dir->cap_len, 80);
    CHECK_INT(dir->wire_len, len_payload);

    return 0;
}

static enum proto_parse_status parse_max_keep(struct parser *parser, struct proto_info unused_ *info,
        unsigned way, uint8_t const *packet, size_t unused_ cap_len, size_t unused_ wire_len,
        struct timeval const unused_ *now, size_t unused_ tot_cap_len, uint8_t const unused_ *tot_packet)
{
    struct streambuf *sbuf = (struct streambuf *)parser;
    streambuf_set_restart(sbuf, way, packet, 1);
    return PROTO_OK;
}

static int check_max_keep(void)
{
    assert(len_payload > 80);
    struct streambuf_unidir *dir = sbuf.dir + 0;
    enum proto_parse_status status;
    status = streambuf_add(&sbuf, (struct parser *)&sbuf, NULL, 0, (uint8_t *)long_payload,
            len_payload, len_payload, &now, len_payload, (uint8_t *)long_payload);
    CHECK_INT(status, PROTO_OK);
    CHECK_INT(dir->cap_len, 80);
    CHECK_INT(dir->wire_len, len_payload);
    return 0;
}

static int parse_last_packet_called = 0;
static enum proto_parse_status parse_last_packet(struct parser *parser, struct proto_info unused_ *info,
        unsigned way, uint8_t const *packet, size_t cap_len, size_t unused_ wire_len,
        struct timeval const unused_ *now, size_t unused_ tot_cap_len, uint8_t const unused_ *tot_packet)
{
    struct streambuf *sbuf = (struct streambuf *)parser;
    struct streambuf_unidir *dir = sbuf->dir + way;
    parse_last_packet_called++;
    SLOG(LOG_DEBUG, "Parse %d called on payload '%.*s', %s", parse_last_packet_called, (int)cap_len,
            packet, streambuf_2_str(sbuf, way));
    if (parse_last_packet_called == 1) {
        assert(packet[0] == 'T');
        assert(dir->cap_len == len_payload);
        assert(dir->buffer_is_malloced == 0);
        streambuf_set_restart(sbuf, way, packet, 1);
        return PROTO_OK;
    };
    if (parse_last_packet_called == 2) {
        assert(packet[0] == 'T');
        assert(dir->wire_len == len_payload * 2);
        assert(dir->cap_len == 80);
        assert(dir->buffer_is_malloced == 1);
        streambuf_set_restart(sbuf, way, packet + len_payload, 0);
        return PROTO_OK;
    }
    if (parse_last_packet_called == 3) {
        assert(packet[0] == 'T');
        assert(dir->wire_len == len_payload);
        assert(dir->cap_len == len_payload);
        assert(dir->buffer_is_malloced == 0);
        streambuf_set_restart(sbuf, way, packet + 100, 0);
        return PROTO_OK;
    }
    if (parse_last_packet_called == 4) {
        assert(packet[0] == 't');
        assert(wire_len == len_payload - 100);
        assert(cap_len == len_payload - 100);
        assert(dir->buffer_is_malloced == 0);
        return PROTO_OK;
    }
    if (parse_last_packet_called == 5) {
        assert(wire_len == len_payload);
        assert(cap_len == len_payload);
        streambuf_set_restart(sbuf, way, packet, 1);
        return PROTO_OK;
    }
    if (parse_last_packet_called == 6) {
        assert(wire_len == len_payload + 300);
        assert(cap_len == 80);
        streambuf_set_restart(sbuf, way, packet + 200, 0);
        return PROTO_OK;
    }
    if (parse_last_packet_called == 7) {
        assert(wire_len == len_payload + 300 - 200);
        assert(cap_len == 0);
        return PROTO_OK;
    }
    // Check that a restart starting on last packet and requiring some bytes after is ok
    // Just buffer to force malloc
    if (parse_last_packet_called == 8) {
        assert(wire_len == len_payload);
        assert(cap_len == len_payload);
        streambuf_set_restart(sbuf, way, packet, len_payload * 2);
        return PROTO_OK;
    }
    // Now, set restart to last packet - 4
    if (parse_last_packet_called == 9) {
        assert(wire_len == len_payload * 2);
        assert(cap_len == 80);
        streambuf_set_restart(sbuf, way, packet + len_payload * 2 - 4, 8);
        return PROTO_OK;
    }
    // The last 4 bytes of the previous packet should be available
    if (parse_last_packet_called == 10) {
        assert(wire_len == 6 + len_payload);
        assert(cap_len == 80);
        assert(packet[0] == 'e');
        return PROTO_OK;
    }
    return PROTO_PARSE_ERR;
}

static int check_last_packet_use(void)
{
    static char payload[] = "This is a very long sentence without much ponctiation so that the parser will not receive it since its buffering would exceed the eighty allowed characters.";
    struct streambuf_unidir *dir = sbuf.dir + 0;
    enum proto_parse_status status;

    status = streambuf_add(&sbuf, (struct parser *)&sbuf, NULL, 0, (uint8_t *)payload, len_payload,
            len_payload, &now, len_payload, (uint8_t *)payload);   // First pkt
    streambuf_keep(&sbuf, 0);
    CHECK_INT(status, PROTO_OK);
    CHECK_INT(dir->cap_len, 80);
    CHECK_INT(dir->wire_len, len_payload);

    status = streambuf_add(&sbuf, (struct parser *)&sbuf, NULL, 0, (uint8_t *)payload, len_payload,
            len_payload, &now, len_payload, (uint8_t *)payload);   // Second one, stream should restart at the start of the second one
    CHECK_INT(parse_last_packet_called, 4);
    CHECK_INT(status, PROTO_OK);
    CHECK_INT(dir->cap_len, 0);
    CHECK_INT(dir->wire_len, 0);

    status = streambuf_add(&sbuf, (struct parser *)&sbuf, NULL, 0, (uint8_t *)payload, len_payload,
            len_payload, &now, len_payload, (uint8_t *)payload);   // Just fill buffer

    status = streambuf_add(&sbuf, (struct parser *)&sbuf, NULL, 0, (uint8_t *)payload, 0,
            300, &now, 0, NULL);   // Push of gap

    // Check that a restart starting on last packet and requiring some bytes after is ok
    status = streambuf_add(&sbuf, (struct parser *)&sbuf, NULL, 0, (uint8_t *)payload, len_payload,
            len_payload, &now, len_payload, (uint8_t *)payload);
    status = streambuf_add(&sbuf, (struct parser *)&sbuf, NULL, 0, (uint8_t *)payload, len_payload,
            len_payload, &now, len_payload, (uint8_t *)payload);
    status = streambuf_add(&sbuf, (struct parser *)&sbuf, NULL, 0, (uint8_t *)payload, 2,
            2, &now, len_payload, (uint8_t *)payload);
    status = streambuf_add(&sbuf, (struct parser *)&sbuf, NULL, 0, (uint8_t *)payload, len_payload,
            len_payload, &now, len_payload, (uint8_t *)payload);

    return 0;
}

typedef int test_fun(void);

int main(void)
{
    log_init();
    ext_init();
    objalloc_init();
    streambuf_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_level(LOG_WARNING, "mutex");
    log_set_level(LOG_WARNING, "redim_array");
    log_set_file("streambuf_check.log");

    test_fun *funs[] = {check_simple, check_vicious, check_drop};
    for (unsigned i = 0; i < NB_ELEMS(funs); ++i) {
        setup(parse);
        assert(0 == funs[i]());
        teardown();
    }

    setup(parse_max_keep);
    assert(0 == check_max_keep());
    teardown();

    setup(parse_last_packet);
    assert(0 == check_last_packet_use());
    teardown();

    streambuf_fini();
    objalloc_fini();
    ext_fini();
    log_fini();
    return EXIT_SUCCESS;
}

