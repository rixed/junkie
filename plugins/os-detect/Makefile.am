AM_CFLAGS = -std=c99 -Wall -W
AM_CPPFLAGS = -I $(top_srcdir)/include -D_GNU_SOURCE

pkglib_LTLIBRARIES = os-detect.la

os_detect_la_SOURCES = os-detect.c
os_detect_la_LDFLAGS = -module -avoid-version

install-exec-local:
	-ln -s $(bindir)/junkie $(bindir)/os-detect
