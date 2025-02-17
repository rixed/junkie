#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_PREREQ([2.71])

# These git commands will disapear from the generated configure script
AC_INIT([junkie],[m4_esyscmd(build-aux/git-version-gen .tarball-version | tr -d '\n')],[rixed-github@happyleptic.org],[],[http://github.com/rixed/junkie])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wno-gnu -Wno-portability foreign subdir-objects])
AM_PROG_AR
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADERS([include/junkie/config.h])
LT_INIT()

AC_SUBST(TAGNAME, m4_esyscmd([git describe --tags || (if git symbolic-ref HEAD >/dev/null 2>&1; then git symbolic-ref HEAD | cut -d/ -f 3- ; else git name-rev HEAD | cut -d' ' -f 2; fi)]))
AC_SUBST(BRANCHNAME, m4_esyscmd([if git symbolic-ref HEAD >/dev/null 2>&1; then git symbolic-ref HEAD | cut -d/ -f 3- ; else git name-rev HEAD | cut -d' ' -f 2; fi]))
AC_SUBST(COMP_HOST, m4_esyscmd([hostname]))

AC_ARG_VAR(GUILE_LOAD_PATH, Where to find the required guile modules (apart from standard paths))

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
LT_INIT

# Checks for libraries.
PKG_CHECK_MODULES([OPENSSL], openssl)
PKG_CHECK_MODULES([GUILE], guile-2.2)
GUILE_MODULE_CHECK([agentx], [(agentx tools)], [current-endianness], [is installed])
AM_CONDITIONAL([WITH_AGENTX], [test x$agentx = xyes])
CPPFLAGS="$GUILE_CFLAGS $OPENSSL_CFLAGS $CPPFLAGS"
LDFLAGS="$GUILE_LIBS $OPENSSL_LIBS $LDFLAGS"
AC_CHECK_LIB(pcap, pcap_activate, , [exit 1])
AC_CHECK_LIB(pthread, pthread_mutex_init, , [exit 1])
AC_CHECK_LIB(ltdl, lt_dlopen, , [exit 1])
AM_ICONV

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h grp.h libgen.h inttypes.h limits.h malloc.h netinet/in.h arpa/inet.h sys/param.h sys/socket.h sys/time.h syslog.h sys/prctl.h pcap.h sys/uio.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_C_BIGENDIAN()

# Checks for library functions.
AC_FUNC_CHOWN
AC_CHECK_FUNCS([clock_gettime localtime_r mkdir regcomp rmdir sqrt strcasecmp strncasecmp strtoull prctl strnstr malloc_stats mallinfo basename_r])

# Some build parameters
AC_ARG_WITH([giant_lock],
      AS_HELP_STRING([--with-giant-lock], [Disable support for multithreaded parsing (which require functionnal timed locks)]))
AS_IF([test "x$with_giant_lock" = "xyes"], [AC_DEFINE([WITH_GIANT_LOCK], [], [Use a giant lock to forbid simultaneous parsing of packets])])

AC_ARG_VAR([CPU_MAX], [Approx of max number of available CPU])
AS_IF([test "x$CPU_MAX" = x], [CPU_MAX="32"])
AC_DEFINE_UNQUOTED([CPU_MAX], [$CPU_MAX], [Approx of max number of available CPU])

# Where to install various things
DEFAULT_GUILELIBDIR="$(guile-config info sitedir)"
AC_ARG_VAR([GUILELIBDIR], [Where to install guile modules [wherever guile-config says]])
AS_IF([test "x$GUILELIBDIR" = x], [if test -n "$DEFAULT_GUILELIBDIR"; then GUILELIBDIR="$DEFAULT_GUILELIBDIR"; else exit 1; fi])
DEFAULT_GUILECACHEDIR="$($GUILE -c '(display (car (last-pair %load-compiled-path)))')"
AC_ARG_VAR([GUILECACHEDIR], [Where to install guile compiled files])
AS_IF([test "x$GUILECACHEDIR" = x], [if test -n "$DEFAULT_GUILECACHEDIR"; then GUILECACHEDIR="$DEFAULT_GUILECACHEDIR"; else exit 1; fi])
AC_ARG_VAR([VARDIR], [Where to store junkie variable state [$(localstatedir)/junkie]])
AS_IF([test "x$VARDIR" = x], [VARDIR='$(localstatedir)/junkie'])


AC_ARG_VAR([CONFDIR], [Where to store configuration files [SYSCONFDIR/junkie]])
AS_IF([test "x$CONFDIR" = x], [CONFDIR="$sysconfdir/junkie"])

case `uname` in
  (Darwin*)
    DEFAULT_LDFLAGS_PLUGIN="-flat_namespace -bundle -undefined suppress"
    DEFAULT_PLUGIN_EXT="bundle" ;;
  (*)
    DEFAULT_LDFLAGS_PLUGIN="-fPIC -shared"
    DEFAULT_PLUGIN_EXT="so" ;;
esac
AC_ARG_VAR([LDFLAGS_PLUGIN], How to link shared libraries)
AS_IF([test "x$LDFLAGS_PLUGIN" = x], [LDFLAGS_PLUGIN="$DEFAULT_LDFLAGS_PLUGIN"])
AC_ARG_VAR([PLUGIN_EXT], Extension of plugins)
AS_IF([test "x$PLUGIN_EXT" = x], [PLUGIN_EXT="$DEFAULT_PLUGIN_EXT"])

AC_ARG_ENABLE(bench, AS_HELP_STRING([--enable-bench],[Include benchmarking code]), [AC_DEFINE([WITH_BENCH], [], [Include benchmarking code])], [])

# Check for PTHREAD_MUTEX_ADAPTIVE_NP
AC_MSG_CHECKING([for PTHREAD_MUTEX_ADAPTIVE_NP])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <pthread.h>
]], [[
  return (PTHREAD_MUTEX_ADAPTIVE_NP);
]])], [
AC_MSG_RESULT([yes])
AC_DEFINE([HAVE_PTHREAD_MUTEX_ADAPTIVE_NP], [], [PTHREAD_MUTEX_ADAPTIVE_NP exists])
], [
AC_MSG_RESULT([no])
])

AC_CONFIG_FILES([
  Makefile
  include/Makefile
  include/junkie/Makefile
  include/junkie/tools/Makefile
  include/junkie/proto/Makefile
  src/Makefile
  src/tools/Makefile
  src/proto/Makefile
  plugins/dumper/Makefile
  plugins/writer/Makefile
  plugins/rater/Makefile
  plugins/arpgraph/Makefile
  plugins/os-detect/Makefile
  plugins/packetogram/Makefile
  plugins/duplicogram/Makefile
  plugins/nettop/Makefile
  plugins/delayogram/Makefile
  plugins/sslogram/Makefile
  config/Makefile
  config/cacti/Makefile
  guile/Makefile
  guile/srfi/Makefile
  guile/junkie/Makefile
  guile/junkie/www/Makefile
  guile/junkie/www/static_files/Makefile
  guile/junkie/netmatch/Makefile
  tests/Makefile
  doc/Makefile
  examples/Makefile
])
AC_OUTPUT
