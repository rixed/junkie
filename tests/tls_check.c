// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#undef NDEBUG
#include <assert.h>
#include <junkie/cpp.h>
#include <junkie/tools/objalloc.h>
#include <junkie/tools/ext.h>
#include <junkie/proto/pkt_wait_list.h>
#include <junkie/proto/cap.h>
#include <junkie/proto/eth.h>
#include <junkie/proto/ip.h>
#include "lib.h"
#include "proto/tls.c"

static void tls_check(void)
{
    struct tls_keyfile keyfile;
    char *passphrase_key = "passphrase.key";
    char *passless_key = "passless.key";
    static struct ip_addr const net = IP4(1, 2, 3, 4);
    static struct ip_addr const mask = IP4(1, 2, 3, 4);
    struct proto proto;
    proto.name = "";
    assert(TLS_OK == tls_keyfile_ctor(&keyfile, passless_key, NULL, &net, &mask, false, &proto));
    assert(TLS_MISSING_PASSPHRASE == tls_keyfile_ctor(&keyfile, passphrase_key, NULL, &net, &mask, false, &proto));
    assert(TLS_OK == tls_keyfile_ctor(&keyfile, passphrase_key, "toto", &net, &mask, false, &proto));
}

int main(void)
{
    log_init();
    ext_init();
    objalloc_init();
    proto_init();
    pkt_wait_list_init();
    ref_init();
    cap_init();
    eth_init();
    ip_init();
    ip6_init();
    tcp_init();
    tls_init();

    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    log_set_level(LOG_DEBUG, NULL);
    log_set_file("tls_check.log");

    tls_check();

    tls_fini();
    tcp_fini();
    ip6_fini();
    ip_fini();
    eth_fini();
    cap_fini();
    ref_fini();
    pkt_wait_list_fini();
    proto_fini();
    objalloc_fini();
    ext_fini();
    log_fini();
    return EXIT_SUCCESS;
}

