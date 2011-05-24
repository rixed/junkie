// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#undef NDEBUG
#include <assert.h>
#include <limits.h>
#include <junkie/tools/miscmacs.h>
#include "proto/liner.c"

static unsigned nb_tokens(char const *buf, size_t buf_sz, struct liner_delimiter_set *delims)
{
    struct liner liner;
    liner_init(&liner, delims, buf, buf_sz);

    unsigned l;
    for (l = 0; !liner_eof(&liner); l++) {
        liner_next(&liner);
    }

    return l;
}

static void check_simple(void)
{
    static char const simple_text[] =
        "Maitre corbeau, sur un arbre perche,\n"
        "Tenait en son bec un fromage.\n"
        "\n";

    struct liner liner;
    struct liner_delimiter unix_eol[] = { { "\n", 1 } };
    struct liner_delimiter_set eols = { 1, unix_eol, false };

    liner_init(&liner, &eols, simple_text, sizeof(simple_text)-1);
    assert(liner_tok_length(&liner) == 36);
    assert(liner_parsed(&liner) == 37);

    liner_next(&liner);
    assert(liner_tok_length(&liner) == 29);

    liner_next(&liner);
    assert(liner_tok_length(&liner) == 0);
    assert(liner_parsed(&liner) == strlen(simple_text));

    assert(nb_tokens(simple_text, sizeof(simple_text)-1, &eols) == 3);
}

static void check_empty(void)
{
    static struct {
        char const *str;
        unsigned nb_lines[2];   // non greedy / greedy
    } line_tests[] = {
        { "", {0,0} }, { "blabla", {1,1} },
        { "\r\n", {1,1} }, { " \r\n", {1,1} } , { " \n", {1,1} },
        { "\r\n\r\n", {2,1} }, { "\n\n", {2,1} }, { "\r\n \n", {2,2} }, { "\n\r\r\n", {2,2} },
    };

    struct liner_delimiter eol[] = { { "\r\n", 2 }, { "\n", 1 } };
    struct liner_delimiter_set eols[2] = { { 2, eol, false }, { 2, eol, true } };

    for (unsigned e = 0; e < NB_ELEMS(line_tests); e++) {
        assert(nb_tokens(line_tests[e].str, strlen(line_tests[e].str), eols+0) == line_tests[e].nb_lines[0]);
        assert(nb_tokens(line_tests[e].str, strlen(line_tests[e].str), eols+1) == line_tests[e].nb_lines[1]);
    }
}

static void check_trunc_delim(void)
{
    static char const text[] = "blabla\r";

    struct liner liner;
    struct liner_delimiter eol[] = { { "\r\n", 2 } };
    struct liner_delimiter_set eols = { 1, eol, true };

    liner_init(&liner, &eols, text, sizeof(text)-1);
}

static void check_restart(void)
{
    static char const text[] = "xxAABxx";

    struct liner_delimiter ab[] = { { "AB", 2 } };
    struct liner_delimiter_set set = { 1, ab, false };

    assert(nb_tokens(text, strlen(text), &set) == 2);
}

static void check_longest_match(void)
{
    static char const text[] = "glopABCpasglop";

    struct liner liner;
    struct liner_delimiter abc[] = { { "ABC", 3 }, {"AB", 2 }, { "A", 1 } };
    struct liner_delimiter_set delims = { 3, abc, true };

    liner_init(&liner, &delims, text, sizeof(text)-1);
    assert(liner.start == text && liner.tok_size == 4);
    liner_next(&liner);
    assert(liner.start == text+7 && liner.tok_size == 7);
}

static void check_termination(void)
{
    static char const text[] = "glopABC_attention_voie_sans_issue";

    struct liner liner;
    struct liner_delimiter abc[] = { { "ABC", 3 }, {"AB", 2 }, { "A", 1 } };
    struct liner_delimiter_set delims = { 3, abc, true };

    liner_init(&liner, &delims, text, INT_MAX);
    assert(liner.start == text && liner.tok_size == 4);
}

static void check_strtoull(void)
{
    struct {
        char const *text;
        int base;
        unsigned long long expected;
        unsigned end_offset;
    } tests[] = {
        // Simple conversions
        { "", 10, 0, 0 }, { "", 16, 0, 0 },
        { "6", 10, 6, 1 }, { "6", 16, 6, 1 },
        { "b", 10, 0, 0 }, { "b", 16, 11, 1 },
        { "12", 10, 12, 2 }, { "12", 16, 18, 2 },
        { "12a", 10, 12, 2 }, { "12a", 16, 298, 3 },
        // With sign
        { "-14", 10, (unsigned long long)-14, 3 },
        { "0", 10, 0, 1 }, { "+0", 10, 0, 2 }, { "-0", 10, 0, 2 },
        // Initial white spaces
        { "  \t3", 10, 3, 4 },
        // Automatic base
        { "0x10", 0, 16, 4 },
        { "010", 0, 8, 3 },
        // Mixing with end of line delimiter
        { "\n123", 10, 0, 0 },
        { "1\n23", 10, 1, 1 },
        { "12\n3", 10, 12, 2 },
        { "123\n", 10, 123, 3 },
        // All of the above
        { " \t +0x1\n6", 0, 1, 7 },
    };

    for (unsigned t = 0; t < NB_ELEMS(tests); t++) {
        struct liner liner;
        liner_init(&liner, &delim_lines, tests[t].text, strlen(tests[t].text));

        char const *end;
        unsigned long long res = liner_strtoull(&liner, &end, tests[t].base);
        assert(res == tests[t].expected);
        assert(end - tests[t].text == tests[t].end_offset);
    }
}

int main(void)
{
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("liner_check.log");

    check_simple();
    check_empty();
    check_trunc_delim();
    check_longest_match();
    check_restart();
    check_termination();
    check_strtoull();

    return EXIT_SUCCESS;
}
