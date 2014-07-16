// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include "proto/cursor.c"

static void cursor_read_string_check(void)
{
    iconv_t iconv_cd = iconv_open("UTF8//IGNORE", "UTF16LE");
    char buf[255];

    struct cursor cursor;
    static uint8_t const data_utf16[] = { 0x57, 0x00, 0x4f, 0x00, 0x52, 0x00,
        0x4b, 0x00, 0x47, 0x00, 0x52, 0x00, 0x4f, 0x00, 0x55, 0x00, 0x50, 0x00 };
    cursor_ctor(&cursor, data_utf16, sizeof(data_utf16));
    assert(18 == cursor_read_fixed_utf16(&cursor, iconv_cd, buf, sizeof(buf), sizeof(data_utf16)));
    assert(0 == strcmp("WORKGROUP", buf));

    static uint8_t const data_null_utf16[] = { 0x00, 0x00 };
    cursor_ctor(&cursor, data_null_utf16, sizeof(data_null_utf16));
    assert(2 == cursor_read_utf16(&cursor, iconv_cd, buf, sizeof(buf), sizeof(data_null_utf16)));
    assert(0 == strcmp("", buf));

    iconv_close(iconv_cd);
}

static void cursor_check(void)
{
    struct cursor cursor;

    static uint8_t const data[] = { 1, 2 };
    cursor_ctor(&cursor, data, sizeof(data));
    assert(cursor_peek_u8(&cursor, 0) == 0x01U);
    assert(cursor_peek_u8(&cursor, 1) == 0x02U);
    assert(cursor_read_u8(&cursor) == 0x01U);
    assert(cursor_read_u8(&cursor) == 0x02U);

    static uint16_t const data16[] = { 0x0102, 0x0304 };
    cursor_ctor(&cursor, (uint8_t *)data16, sizeof(data16));
    assert(cursor_peek_u16le(&cursor, 0) == 0x0102U);
    assert(cursor_peek_u16le(&cursor, 2) == 0x0304U);
    assert(cursor_read_u16(&cursor) == 0x0102U);
    assert(cursor_read_u16(&cursor) == 0x0304U);

    static uint32_t const data32[] = { 0x01020304U, 0x05060708U };
    cursor_ctor(&cursor, (uint8_t *)data32, sizeof(data32));
    assert(cursor_peek_u32le(&cursor, 0) == 0x01020304U);
    assert(cursor_peek_u32le(&cursor, 4) == 0x05060708U);
    assert(cursor_read_u32(&cursor) == 0x01020304U);
    assert(cursor_read_u32(&cursor) == 0x05060708U);

    static uint64_t const data64[] = { 0x0102030405060708ULL };
    cursor_ctor(&cursor, (uint8_t *)data64, sizeof(data64));
    assert(cursor_peek_u64le(&cursor, 0) == 0x0102030405060708ULL);
    assert(cursor_read_u64(&cursor) == 0x0102030405060708ULL);

    static uint8_t const datan[] = { 1, 2, 3, 4 };
    cursor_ctor(&cursor, datan, sizeof(datan));
    assert(cursor_peek_u32n(&cursor, 0) == 0x01020304);
    assert(cursor_read_u32n(&cursor) == 0x01020304);

    cursor_ctor(&cursor, datan, sizeof(datan));
    assert(cursor_peek_u16n(&cursor, 0) == 0x0102);
    assert(cursor_read_u16n(&cursor) == 0x0102);
}

int main(void)
{
    log_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("cursor_check.log");

    cursor_check();
    cursor_read_string_check();

    log_fini();
    return EXIT_SUCCESS;
}

