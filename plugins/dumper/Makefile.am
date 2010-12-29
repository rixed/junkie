AM_CFLAGS = -std=c99 -Wall -W
AM_CPPFLAGS = -I $(top_srcdir)/include -D_GNU_SOURCE

lib_LTLIBRARIES = dumper.la

dumper_la_SOURCES = dumper.c
dumper_la_LDFLAGS = -module -avoid-version

