AM_CFLAGS = -std=c99 -Wall -W
AM_CPPFLAGS = -I $(top_srcdir)/include -D_GNU_SOURCE

lib_LTLIBRARIES = libjunkietools.la

libjunkietools_la_SOURCES = \
	files.c hash.c ip_addr.c \
	log.c mallocer.c mutex.c redim_array.c \
	tempstr.c timeval.c ext.c cli.c ref.c \
	sock.c serialization.c netflow.c \
	objalloc.c proto.c bench.c proto_stack.c \
	term.c timebound.c string.c string_buffer.c
libjunkietools_la_LDFLAGS = --export-dynamic

