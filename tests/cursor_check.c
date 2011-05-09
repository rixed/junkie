// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include "proto/cursor.c"

static void cursor_check(void)
{
	struct cursor cursor;

    static uint8_t const data[] = { 1, 2 };
	cursor_ctor(&cursor, data, sizeof(data));
	assert(cursor_read_u8(&cursor) == 0x01U);
	assert(cursor_read_u8(&cursor) == 0x02U);

    static uint16_t const data16[] = { 0x0102, 0x0304 };
	cursor_ctor(&cursor, (uint8_t *)data16, sizeof(data16));
	assert(cursor_read_u16(&cursor) == 0x0102U);
	assert(cursor_read_u16(&cursor) == 0x0304U);

    static uint32_t const data32[] = { 0x01020304U, 0x05060708U };
	cursor_ctor(&cursor, (uint8_t *)data32, sizeof(data32));
	assert(cursor_read_u32(&cursor) == 0x01020304U);
	assert(cursor_read_u32(&cursor) == 0x05060708U);

    static uint64_t const data64[] = { 0x0102030405060708ULL };
	cursor_ctor(&cursor, (uint8_t *)data64, sizeof(data64));
	assert(cursor_read_u64(&cursor) == 0x0102030405060708ULL);

	static uint8_t const datan[] = { 1, 2, 3, 4 };
	cursor_ctor(&cursor, datan, sizeof(datan));
	assert(cursor_read_u32n(&cursor) == 0x01020304);

	cursor_ctor(&cursor, datan, sizeof(datan));
	assert(cursor_read_u16n(&cursor) == 0x0102);
}

int main(void)
{
    log_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("cursor_check.log");

    cursor_check();

    log_fini();
    return EXIT_SUCCESS;
}
