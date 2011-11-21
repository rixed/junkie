AM_CFLAGS = -std=c99 -Wall -W
AM_CPPFLAGS = -I $(top_srcdir)/include -D_GNU_SOURCE

noinst_LTLIBRARIES = libtools.la

libtools_la_SOURCES = \
	files.c hash.c ip_addr.c jhash.c \
	log.c mallocer.c mutex.c redim_array.c \
	tempstr.c timeval.c ext.c cli.c ref.c \
	sock.c serialize.c
libtools_la_LDFLAGS = --export-dynamic
