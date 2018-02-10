AM_CFLAGS = -std=c99 -Wall -W
AM_CPPFLAGS = -I $(top_srcdir)/include -D_GNU_SOURCE

pkglib_LTLIBRARIES = packetogram.la

packetogram_la_SOURCES = packetogram.c
packetogram_la_LDFLAGS = -module -avoid-version

install-exec-local:
	-ln -s $(bindir)/junkie $(bindir)/packetogram
