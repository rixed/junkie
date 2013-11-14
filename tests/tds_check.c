// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#undef NDEBUG
#include <assert.h>
#include <time.h>
#include <junkie/cpp.h>
#include <junkie/tools/ext.h>
#include <junkie/tools/objalloc.h>
#include <junkie/proto/cursor.h>
#include <junkie/proto/tcp.h>
#include <junkie/proto/ip.h>
#include <junkie/proto/eth.h>
#include <junkie/proto/pkt_wait_list.h>
#include "lib.h"
#include "proto/tds.c"
#include "proto/tds_msg.c"

static void str_check(void)
{
    static uint8_t unicode_strings[] =
        "e\0t\0r\0o\0n\0"   // 5 chars
        "e\0t\0r\0o\0n\0"   // 5 chars
        "p\0e\0t\0i\0t\0p\0a\0t\0a\0p\0o\0n\0"; // 12 chars

    struct cursor cursor;
    cursor_ctor(&cursor, unicode_strings, sizeof(unicode_strings));
    size_t len = 0;
    char big[22+1];
    append_from_unicode(big, sizeof(big), &len, &cursor, 5);
    assert(0 == strcmp(big, "etron"));
    append_from_unicode(big, sizeof(big), &len, &cursor, 5);
    assert(0 == strcmp(big, "etronetron"));
    append_from_unicode(big, sizeof(big), &len, &cursor, 12);
    assert(0 == strcmp(big, "etronetronpetitpatapon"));

    cursor_ctor(&cursor, unicode_strings, sizeof(unicode_strings));
    len = 0;
    char sht[10+1]; // place for two
    append_from_unicode(sht, sizeof(sht), &len, &cursor, 5);
    append_from_unicode(sht, sizeof(sht), &len, &cursor, 5);
    append_from_unicode(sht, sizeof(sht), &len, &cursor, 12);
    assert(0 == strcmp(sht, "etronetron"));

    cursor_ctor(&cursor, unicode_strings, sizeof(unicode_strings));
    len = 0;
    char tny[2+1];
    append_from_unicode(tny, sizeof(tny), &len, &cursor, 5);
    append_from_unicode(tny, sizeof(tny), &len, &cursor, 5);
    append_from_unicode(tny, sizeof(tny), &len, &cursor, 12);
    assert(0 == strcmp(tny, "et"));
}

int main(void)
{
    log_init();
    ext_init();
    objalloc_init();
    ref_init();
    proto_init();
    port_muxer_init();
    pkt_wait_list_init();
    streambuf_init();
    eth_init();
    ip_init();
    ip6_init();
    tcp_init();
    tds_init();
    tds_msg_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("tds_check.log");

    str_check();
    stress_check(proto_tds);
    stress_check(proto_tds_msg);

    doomer_stop();
    tds_msg_fini();
    tds_fini();
    tcp_fini();
    ip6_fini();
    ip_fini();
    eth_fini();
    streambuf_fini();
    pkt_wait_list_fini();
    port_muxer_fini();
    proto_fini();
    ref_fini();
    objalloc_fini();
    ext_fini();
    log_fini();
    return EXIT_SUCCESS;
}
