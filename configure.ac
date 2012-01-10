#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_PREREQ([2.65])

# These git commands will disapear from the generated configure script
AC_INIT([junkie],
		m4_esyscmd([build-aux/git-version-gen .tarball-version | tr -d '\n']),
		github@securactive.net, , http://github.com/securactive/junkie)
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall foreign])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADERS([include/junkie/config.h])
LT_INIT()

AC_SUBST(TAGNAME, m4_esyscmd([git describe --tags || (if git symbolic-ref HEAD >/dev/null 2>&1; then git symbolic-ref HEAD | cut -d/ -f 3- ; else git name-rev HEAD | cut -d' ' -f 2; fi)]))
AC_SUBST(BRANCHNAME, m4_esyscmd([if git symbolic-ref HEAD >/dev/null 2>&1; then git symbolic-ref HEAD | cut -d/ -f 3- ; else git name-rev HEAD | cut -d' ' -f 2; fi]))
AC_SUBST(COMP_HOST, m4_esyscmd([hostname]))

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL

# Checks for libraries.
AC_CHECK_LIB(ssl, SHA1, , AC_CHECK_LIB(crypto, SHA1, , [exit 1]))
AC_CHECK_LIB(pcap, pcap_activate, , [exit 1])
CFLAGS="$(guile-config compile) $CFLAGS"
LDFLAGS="$(guile-config link) $LDFLAGS"
AC_CHECK_LIB(pthread, pthread_mutex_init, , [exit 1])
AC_CHECK_LIB(ltdl, lt_dlopen, , [exit 1])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h grp.h libgen.h inttypes.h limits.h malloc.h netinet/in.h arpa/inet.h sys/param.h sys/socket.h sys/time.h syslog.h sys/prctl.h pcap.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_C_BIGENDIAN()

# Checks for library functions.
AC_FUNC_CHOWN
AC_CHECK_FUNCS([clock_gettime localtime_r mkdir regcomp rmdir sqrt strcasecmp strncasecmp strtoull prctl strnstr malloc_stats mallinfo])

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

AC_ARG_VAR([CONFDIR], [Where to store configuration files [SYSCONFDIR/junkie]])
AS_IF([test "x$CONFDIR" = x], [CONFDIR="$sysconfdir/junkie"])


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
	plugins/serializer/Makefile
	config/Makefile
	guile/Makefile
	guile/srfi/Makefile
	guile/junkie/Makefile
	guile/junkie/www/Makefile
	guile/junkie/www/static_files/Makefile
	guile/junkie/writer/Makefile
	guile/junkie/netmatch/Makefile
	tests/Makefile
])
AC_OUTPUT
