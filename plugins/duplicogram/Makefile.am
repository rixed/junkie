AM_CFLAGS = -std=c99 -Wall -W
AM_CPPFLAGS = -I $(top_srcdir)/include -D_GNU_SOURCE

pkglib_LTLIBRARIES = duplicogram.la

duplicogram_la_SOURCES = duplicogram.c
duplicogram_la_LDFLAGS = -module -avoid-version

install-exec-local:
	-ln -s $(bindir)/junkie $(bindir)/duplicogram
