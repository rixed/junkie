AM_CFLAGS = -std=c99 -Wall -W
AM_CPPFLAGS = -I $(top_srcdir)/include -D_GNU_SOURCE

pkglib_LTLIBRARIES = writer.la

writer_la_SOURCES = writer.c
writer_la_LDFLAGS = -module -avoid-version

install-exec-local:
	-ln -s $(bindir)/junkie $(bindir)/writer
