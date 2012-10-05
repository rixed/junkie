SUBDIRS = tools proto .

AM_CFLAGS = -std=c99 -Wall -W
AM_CPPFLAGS = -I $(top_srcdir)/include -D_GNU_SOURCE \
              -DTAGNAME=@TAGNAME@ -DBRANCHNAME=@BRANCHNAME@ -DCOMP_HOST=@COMP_HOST@ \
              -DSYSCONFDIR=$(sysconfdir) -DPKGLIBDIR=$(pkglibdir)

bin_PROGRAMS = junkie
dist_bin_SCRIPTS = juncli

junkie_SOURCES = \
	digest_queue.c \
	main.c \
	pkt_source.c pkt_source.h \
	plugins.c plugins.h \
	netmatch.c nettrack.c nettrack.h \
	hook.h

junkie_LDADD = proto/libproto.la tools/libjunkietools.la -lm
junkie_LDFLAGS = -export-dynamic

