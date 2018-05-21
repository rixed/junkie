AM_CFLAGS = -std=c99 -Wall -W
AM_CPPFLAGS = -I $(top_srcdir)/include -D_GNU_SOURCE

pkglib_LTLIBRARIES = sslogram.la

sslogram_la_SOURCES = sslogram.c
sslogram_la_LDFLAGS = -module -avoid-version

install-exec-local:
	-ln -s $(bindir)/junkie $(bindir)/sslogram
