AM_CFLAGS = -std=c99 -Wall -W
AM_CPPFLAGS = -I $(top_srcdir)/include -D_GNU_SOURCE

lib_LTLIBRARIES = libjunkietools.la

libjunkietools_la_SOURCES = \
	files.c hash.c ip_addr.c jhash.c \
	log.c mallocer.c mutex.c redim_array.c \
	tempstr.c timeval.c ext.c cli.c ref.c \
	sock.c serialization.c netflow.c \
	objalloc.c proto.c bench.c
libjunkietools_la_LDFLAGS = --export-dynamic

