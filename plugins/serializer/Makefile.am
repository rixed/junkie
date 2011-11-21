AM_CFLAGS = -std=c99 -Wall -W
AM_CPPFLAGS = -I $(top_srcdir)/include -D_GNU_SOURCE

pkglib_LTLIBRARIES = serializer.la

serializer_la_SOURCES = serializer.c
serializer_la_LDFLAGS = -module -avoid-version

