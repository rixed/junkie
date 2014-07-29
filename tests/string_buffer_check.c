// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "junkie/tools/string_buffer.h"
#include "junkie/tools/log.h"
#include "junkie/tools/miscmacs.h"

static void check_string_buffer(struct string_buffer const *buffer, char const *expected, bool truncated)
{
    if (buffer->truncated != truncated) {
        printf("Buffer %s should %s be truncated\n", string_buffer_2_str(buffer), truncated ? "" : "not");
        assert(truncated == buffer->truncated);
    }
    if (0 != strcmp(buffer_get_string(buffer), expected)) {
        printf("Buffer %s string should be '%s'\n", string_buffer_2_str(buffer), expected);
        assert(0 == strcmp(buffer->head, expected));
    }
}

static void string_buffer_append_small_unicode_check(void)
{
    struct string_buffer buffer;
    char buf[8];
    string_buffer_ctor(&buffer, buf, sizeof(buf));
    const char src[] = {0x54, 0x00, 0x6f, 0x00, 0x74, 0x00, 0x6f, 0x00};
    iconv_t cd = iconv_open("UTF8", "UCS2");
    size_t written = buffer_append_unicode(&buffer, cd, src, sizeof(src));
    assert(written == 4);
    check_string_buffer(&buffer, "Toto", false);
    written = buffer_append_unicode(&buffer, cd, src, 6);
    assert(written == 3);
    check_string_buffer(&buffer, "TotoTot", false);
    written = buffer_append_unicode(&buffer, cd, src, 4);
    assert(written == 0);
    check_string_buffer(&buffer, "TotoTot", true);
    iconv_close(cd);
}

static void string_buffer_append_unicode_truncated(void)
{
    iconv_t cd = iconv_open("UTF8", "UTF8");
    struct string_buffer buffer;
    char buf[8];
    string_buffer_ctor(&buffer, buf, sizeof(buf));
    const char ellipsis[] = {0xe2, 0x80, 0xa6};
    buffer_append_unicode(&buffer, cd, ellipsis, sizeof(ellipsis));
    check_string_buffer(&buffer, "…", false);
    buffer_append_unicode(&buffer, cd, "a", 1);
    check_string_buffer(&buffer, "…a", false);
    buffer_append_unicode(&buffer, cd, "bc", 2);
    check_string_buffer(&buffer, "…abc", false);
    buffer_append_unicode(&buffer, cd, ellipsis, sizeof(ellipsis));
    check_string_buffer(&buffer, "…abc", true);
    iconv_close(cd);
}

static void string_buffer_append_unicode_check_2(void)
{
    iconv_t cd = iconv_open("UTF8", "UCS2");
    static const char unicode_strings[] =
        "o\0c\0t\0o\0n\0"   // 5 chars
        "o\0c\0t\0o\0n\0"   // 5 chars
        "p\0e\0t\0i\0t\0p\0a\0t\0a\0p\0o\0n\0"; // 12 chars
    char big[22+1];
    struct string_buffer buffer;
    string_buffer_ctor(&buffer, big, sizeof(big));
    memset(big, 'x', sizeof(big));
    buffer_append_unicode(&buffer, cd, unicode_strings, 10);
    check_string_buffer(&buffer, "octon", false);
    buffer_append_unicode(&buffer, cd, unicode_strings + 10, 10);
    check_string_buffer(&buffer, "octonocton", false);
    buffer_append_unicode(&buffer, cd, unicode_strings + 20, 24);
    check_string_buffer(&buffer, "octonoctonpetitpatapon", false);

    char sht[10+1]; // place for two
    memset(sht, 'x', sizeof(sht));
    string_buffer_ctor(&buffer, sht, sizeof(sht));
    buffer_append_unicode(&buffer, cd, unicode_strings, 10);
    check_string_buffer(&buffer, "octon", false);
    buffer_append_unicode(&buffer, cd, unicode_strings + 10, 10);
    buffer_append_unicode(&buffer, cd, unicode_strings + 20, 24);
    check_string_buffer(&buffer, "octonocton", true);

    char tny[2+1];
    string_buffer_ctor(&buffer, tny, sizeof(tny));
    memset(tny, 'x', sizeof(tny));
    buffer_append_unicode(&buffer, cd, unicode_strings, 10);
    buffer_append_unicode(&buffer, cd, unicode_strings + 10, 10);
    buffer_append_unicode(&buffer, cd, unicode_strings + 20, 24);
    check_string_buffer(&buffer, "oc", true);
    iconv_close(cd);
}

static void string_buffer_append_ucs2_check(void)
{
    iconv_t cd = iconv_open("UTF8", "UCS2");
    static char str[] = {
        0x53,0x00,0x45,0x00,0x4c,0x00,0x45,0x00,0x43,0x00,0x54,0x00,0x20,0x00,0x2a,0x00,
        0x20,0x00,0x46,0x00,0x52,0x00,0x4f,0x00,0x4d,0x00,0x20,0x00,0x54,0x00,0x6f,0x00,
        0x74,0x00,0x6f,0x00,0x20,0x00,0x57,0x00,0x48,0x00,0x45,0x00,0x52,0x00,0x45,0x00,
        0x20,0x00,0x6e,0x00,0x61,0x00,0x6d,0x00,0x65,0x00,0x20,0x00,0x3d,0x00,0x20,0x00,
        0x27,0x00,0x72,0x00,0xe9,0x00,0x70,0x00,0xe9,0x00,0x74,0x00,0xe9,0x00,0x73,0x00,
        0x27,0x00 };
    char dst[0x52];
    memset(dst, 'x', sizeof(dst));
    struct string_buffer buffer;
    string_buffer_ctor(&buffer, dst, sizeof(dst));
    buffer_append_unicode(&buffer, cd, (char*) str, sizeof(str));
    check_string_buffer(&buffer, "SELECT * FROM Toto WHERE name = 'répétés'", false);

    static char str_2[] = {
        0x6b, 0x00, 0x75, 0x00, 0x0a, 0x00, 0x7a, 0x00
    };
    string_buffer_ctor(&buffer, dst, sizeof(dst));
    buffer_append_unicode(&buffer, cd, str_2, sizeof(str_2));
    check_string_buffer(&buffer, "ku\nz", false);

    iconv_close(cd);
}

static void string_buffer_append_hex_check(void)
{
    struct string_buffer buffer;
    char buf[17];
    memset(buf, 'x', sizeof(buf));
    string_buffer_ctor(&buffer, buf, sizeof(buf));

    static const char src[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
    size_t written = buffer_append_hexstring(&buffer, src, 5);
    assert(written == 12);
    check_string_buffer(&buffer, "0x0102030405", false);

    written = buffer_append_hexstring(&buffer, src, 2);
    assert(written == 4);
    check_string_buffer(&buffer, "0x01020304050x01", true);

    static const char src_2[] = { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff };
    char dst[22+1];
    memset(dst, 'x', sizeof(dst));
    string_buffer_ctor(&buffer, dst, sizeof(dst));
    buffer_append_hexstring(&buffer, src_2, 5);
    check_string_buffer(&buffer, "0x0011223344", false);
}

static void string_buffer_append_string_check(void)
{
    struct string_buffer buffer;
    char buf[10];
    memset(buf, 'x', sizeof(buf));
    string_buffer_ctor(&buffer, buf, sizeof(buf));
    size_t written = buffer_append_string(&buffer, "first");
    assert(written == 5);
    check_string_buffer(&buffer, "first", false);
    written = buffer_append_string(&buffer, "sec");
    assert(written == 3);
    check_string_buffer(&buffer, "firstsec", false);
    written = buffer_append_string(&buffer, "overflow");
    assert(written == 1);
    check_string_buffer(&buffer, "firstseco", true);
}

static void string_buffer_append_stringn_with_null_check(void)
{
    struct string_buffer buffer;
    char buf[10];
    memset(buf, 'x', sizeof(buf));
    string_buffer_ctor(&buffer, buf, sizeof(buf));
    size_t written = buffer_append_stringn(&buffer, "fir\0st", 6);
    assert(written == 3);
    check_string_buffer(&buffer, "fir", false);
    written = buffer_append_stringn(&buffer, "sec", 3);
    assert(written == 3);
    check_string_buffer(&buffer, "firsec", false);
    written = buffer_append_stringn(&buffer, "ove\0rflow", 9);
    assert(written == 3);
    check_string_buffer(&buffer, "firsecove", false);
}

static void string_buffer_append_stringn_check(void)
{
    struct string_buffer buffer;
    char buf[5];
    memset(buf, 'x', sizeof(buf));
    string_buffer_ctor(&buffer, buf, sizeof(buf));
    size_t written = buffer_append_stringn(&buffer, "tot", sizeof("tot"));
    assert(written == 3);
    written = buffer_append_stringn(&buffer, "lol", sizeof("lol"));
    assert(written == 1);
}

static void string_buffer_rollback_check(void)
{
    struct string_buffer buffer;
    char buf[10];
    string_buffer_ctor(&buffer, buf, sizeof(buf));
    buffer_append_stringn(&buffer, "octonions", sizeof("octonions"));
    buffer_rollback(&buffer, 3);
    check_string_buffer(&buffer, "octoni", false);
    buffer_append_stringn(&buffer, "octonions", sizeof("octonions"));
    check_string_buffer(&buffer, "octonioct", true);
    buffer_rollback(&buffer, 7);
    check_string_buffer(&buffer, "oc", true);
    buffer_rollback(&buffer, 5);
    check_string_buffer(&buffer, "", true);
}

static void string_buffer_rollback_utf8_check(void)
{
    struct string_buffer buffer;
    char buf[12];
    memset(buf, 'x', sizeof(buf));
    string_buffer_ctor(&buffer, buf, sizeof(buf));
    const char ellipsis[] = {0xe2, 0x80, 0xa6};
    buffer_append_stringn(&buffer, ellipsis, sizeof(ellipsis));
    buffer_append_string(&buffer, "do");
    buffer_append_stringn(&buffer, ellipsis, sizeof(ellipsis));
    check_string_buffer(&buffer, "…do…", false);
    buffer_append_stringn(&buffer, ellipsis, 2);
    buffer_rollback_utf8_char(&buffer, 1);
    check_string_buffer(&buffer, "…do…", false);
    buffer_rollback_utf8_char(&buffer, 1);
    check_string_buffer(&buffer, "…do", false);
    buffer_rollback_utf8_char(&buffer, 2);
    check_string_buffer(&buffer, "…", false);
    buffer_rollback_utf8_char(&buffer, 2);
    check_string_buffer(&buffer, "", false);
    buffer_rollback_utf8_char(&buffer, 1);
    check_string_buffer(&buffer, "", false);
}

static void string_buffer_printf_check(void)
{
    struct string_buffer buffer;
    char buf[15];
    memset(buf, 'x', sizeof(buf));
    string_buffer_ctor(&buffer, buf, sizeof(buf));
    buffer_append_printf(&buffer, "%d, %s", 4, "test");
    check_string_buffer(&buffer, "4, test", false);
    buffer_append_printf(&buffer, ", %d, %s", 5, "test2");
    check_string_buffer(&buffer, "4, test, 5, te", true);
}

static void string_buffer_rollback_incomplete_utf8_check(void)
{
    struct string_buffer buffer;
    char buf[12];
    memset(buf, 'x', sizeof(buf));
    string_buffer_ctor(&buffer, buf, sizeof(buf));
    const char ellipsis[] = {0xe2, 0x80, 0xa6};
    buffer_append_stringn(&buffer, ellipsis, sizeof(ellipsis));
    // Rollback of incomplete 3 bytes char
    buffer_append_stringn(&buffer, ellipsis, 2);
    buffer_rollback_incomplete_utf8_char(&buffer);
    check_string_buffer(&buffer, "…", false);
    // Character is complete, should not rollback
    buffer_append_stringn(&buffer, "ἀ", 3);
    buffer_rollback_incomplete_utf8_char(&buffer);
    check_string_buffer(&buffer, "…ἀ", false);
}

static struct escape_test {
    char const *text;
    char const *expected;
    size_t buffer_size;
    bool truncated;
    bool expected_truncated;
    bool normalize;
    char quoted_char;
} escape_test[] = {
    { "tot\"o" , "tot\"\"" , 6 , false , true , true , '"'}  ,
    { "t'ot\"o" , "t''ot"    , 6 , false , true , true , '\''} ,
};

static void string_buffer_escape_quotes_check(void)
{
    for (unsigned cur_test = 0; cur_test < NB_ELEMS(escape_test); cur_test++) {
        printf("Check escape csv %u\n", cur_test);
        struct escape_test test = escape_test[cur_test];
        char dst[test.buffer_size];
        struct string_buffer buffer;
        string_buffer_ctor(&buffer, dst, sizeof(dst));
        buffer_append_escape_quotes(&buffer, test.text, strlen(test.text) + 1, test.quoted_char, test.normalize);
        check_string_buffer(&buffer, test.expected, test.expected_truncated);
    }
}

int main(void)
{
    log_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("string_buffer_check.log");

    string_buffer_append_string_check();
    string_buffer_append_stringn_check();
    string_buffer_append_hex_check();
    string_buffer_append_small_unicode_check();
    string_buffer_append_unicode_check_2();
    string_buffer_append_ucs2_check();
    string_buffer_append_unicode_truncated();
    string_buffer_rollback_check();
    string_buffer_rollback_utf8_check();
    string_buffer_rollback_incomplete_utf8_check();
    string_buffer_escape_quotes_check();
    string_buffer_printf_check();
    string_buffer_append_stringn_with_null_check();

    log_fini();
    return EXIT_SUCCESS;
}

