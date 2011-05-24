// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <junkie/tools/miscmacs.h>
#include <junkie/tools/log.h>

static void endianness_check(void)
{
    uint64_t values[] = {
        0x0, 0x10, 0x200, 0x3000, 0x40000, 0x50000, 0x6000000, 0x70000000, 0x800000000,
        0x9000000000, 0xA0000000000, 0xB00000000000, 0xC000000000000, 0xD0000000000000,
        0xE000000000000000
    };
    for (unsigned u=0; u < NB_ELEMS(values); u++) {
        uint8_t u8 = READ_U8(values+u);
        uint16_t u16 = READ_U16(values+u);
        uint32_t u24 = READ_U24(values+u);
        uint32_t u32 = READ_U32(values+u);
        uint64_t u64 = READ_U64(values+u);
        assert(u8  == values[u] % 0x100ULL);
        assert(u16 == values[u] % 0x10000ULL);
        assert(u24 == values[u] % 0x1000000ULL);
        assert(u32 == values[u] % 0x100000000ULL);
        assert(u64 == values[u]);
    }
}

int main(void)
{
    log_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("endianness_check.log");

    endianness_check();

    log_fini();
    return EXIT_SUCCESS;
}

