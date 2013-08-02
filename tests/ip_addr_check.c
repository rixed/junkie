// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#undef NDEBUG
#include <assert.h>
#include <junkie/cpp.h>
#include "tools/ip_addr.c"

static struct ip_addr const a = { .family = AF_INET, .u = { .v4 = { 0x0101A8C0 } }};
static struct ip_addr const b = { .family = AF_INET, .u = { .v4 = { 0x0201A8C0 } }};

static void ip_addr_cmp_check_(struct ip_addr const *a, struct ip_addr const *b, int expected)
{
    int cmp = ip_addr_cmp(a, b);
    assert(cmp == expected);
}

static void ip_addr_check(void)
{
    ip_addr_cmp_check_(&a, &a, 0);
    ip_addr_cmp_check_(&a, &b, -1);
    ip_addr_cmp_check_(&b, &a, 1);

    assert(!ip_addr_is_v6(&a) && !ip_addr_is_v6(&b));
}

static void ip_addr_ctor_from_str_check(void)
{
    static struct {
        char const *str;
        int mode;
    } const tests[] = {
        { "0.0.0.0",        4, },
        { "1.2.3.4",        4, },
        { "0.0.0.1",        4, },
        { "128.2.1.255",    4, },
        { "::ffff:1.2.3.4", 6, },
    };

    for (unsigned t = 0; t < NB_ELEMS(tests); t++) {
        struct ip_addr addr;
        ip_addr_ctor_from_str(&addr, tests[t].str, strlen(tests[t].str), tests[t].mode );
        char const *str = ip_addr_2_str(&addr);
        SLOG(LOG_DEBUG, "Comparing '%s' with '%s'", tests[t].str, str);
        assert(0 == strcmp(str, tests[t].str));
    }
}

static void ip_addr_routable_check(void)
{
    static struct {
        char const *str;
        int mode;
        bool routable;
    } const tests[] = {
        { "0.0.0.0",        4, true },
        { "1.2.3.4",        4, true },
        { "0.0.0.1",        4, true },
        { "128.2.1.255",    4, true },
        { "::ffff:1.2.3.4", 6, true },
        { "127.0.0.1",      4, false },
        { "172.24.5.4",     4, false },
        { "192.168.10.9",   4, false },
    };

    for (unsigned t = 0; t < NB_ELEMS(tests); t++) {
        struct ip_addr addr;
        ip_addr_ctor_from_str(&addr, tests[t].str, strlen(tests[t].str), tests[t].mode);
        assert(ip_addr_is_routable(&addr) == tests[t].routable);
    }
}

static void broadcast_check(void)
{
    struct {
        int version;
        char const *str;
        uint32_t netmask;
        bool is_broadcast;
    } tests[] = {
        { 4, "1.0.0.0",        0xff000000U, false },
        { 4, "127.0.0.1",      0xff000000U, false },
        { 4, "128.10.5.255",   0xffff0000U, false },
        { 4, "192.168.10.9",   0xffffff00U, false },
        { 4, "10.255.255.255", 0xff000000U, true  },
        { 4, "127.0.255.255",  0xff000000U, false },
        { 4, "128.0.255.255",  0xffff0000U, true  },
        { 4, "192.168.10.255", 0xffffff00U, true  },
        { 6, "ff02::1",        0,           true  },
        { 6, "1:2:3:4::",      0,           false },
    };

    for (unsigned t = 0; t < NB_ELEMS(tests); t++) {
        struct ip_addr addr;
        ip_addr_ctor_from_str(&addr, tests[t].str, strlen(tests[t].str), tests[t].version);
        if (addr.family == AF_INET) {
            assert(netmask_of_address(addr.u.v4) == tests[t].netmask);
        }
        assert(ip_addr_is_broadcast(&addr) == tests[t].is_broadcast);
    }
}

static void scm_conv_check(void)
{
    scm_init_guile();
    static struct {
        int version;
        char const *str;
        char const *num;
    } tests[] = {
        { 4, "1.0.0.0", "(2 . 16777216)" },
        { 4, "127.0.0.1", "(2 . 2130706433)" },
        { 4, "128.10.5.255", "(2 . 2148140543)" },
        { 6, "ff02::1", "(10 . 338963523518870617245727861364146307073)" },
        { 6, "1:2:3:4::", "(10 . 5192455318486707403025865779445760)" },
    };

    for (unsigned t = 0; t < NB_ELEMS(tests); t++) {
        struct ip_addr addr;
        ip_addr_ctor_from_str(&addr, tests[t].str, strlen(tests[t].str), tests[t].version);
        SCM ip = scm_from_ip_addr(&addr);
        SCM str = scm_simple_format(SCM_BOOL_F, scm_from_latin1_string("~a"), scm_cons(ip, SCM_EOL));
        char buf[256];
        size_t len = scm_to_locale_stringbuf(str, buf, sizeof(buf));
        assert(len < sizeof(buf));
        buf[len] = '\0';
        printf("%s -> '%s' (expected '%s')\n", tests[t].str, buf, tests[t].num);
        assert(0 == strcmp(tests[t].num, buf));
    }
}

int main(void)
{
    log_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("ip_addr_check.log");

    ip_addr_check();
    ip_addr_ctor_from_str_check();
    ip_addr_routable_check();
    broadcast_check();
    scm_conv_check();

    log_fini();
    return EXIT_SUCCESS;
}
