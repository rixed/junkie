AM_CFLAGS = -std=c99 -Wall -W
AM_CPPFLAGS = -I $(top_srcdir)/include -D_GNU_SOURCE

pkglib_LTLIBRARIES = nettrack.la

nettrack_la_SOURCES = nettrack.c
nettrack_la_LDFLAGS = -module -avoid-version

