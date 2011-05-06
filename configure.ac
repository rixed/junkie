#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_PREREQ([2.65])

# These git commands will disapear from the generated configure script
AC_INIT(junkie, m4_esyscmd([(git describe --tags || (if git symbolic-ref HEAD >/dev/null 2>&1; then git symbolic-ref HEAD | cut -d/ -f 3- ; else git name-rev HEAD | cut -d' ' -f 2; fi)) | tr -d '\n']), github@securactive.net, , http://github.com/securactive/junkie)
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
AC_CHECK_LIB(ssl, SHA1, , [exit 1])
AC_CHECK_LIB(pcap, pcap_activate, , [exit 1])
AC_CHECK_LIB(guile, scm_with_guile,
	[
		CFLAGS="$(guile-config compile) $CFLAGS"
		LDFLAGS="$(guile-config link) $LDFLAGS"
	], [exit 1])
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

# Where to install various things
AC_ARG_VAR([CONFDIR], [Where to store configuration files [SYSCONFDIR/junkie]])
AS_IF([test "x$CONFDIR" = x], [CONFDIR="$sysconfdir/junkie"])

AC_CONFIG_FILES([
	Makefile
	include/Makefile
	src/Makefile
	src/tools/Makefile
	src/proto/Makefile
	plugins/dumper/Makefile
	plugins/writer/Makefile
	plugins/rater/Makefile
	config/Makefile
	tests/Makefile
])
AC_OUTPUT
