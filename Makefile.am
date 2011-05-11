AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

dist_doc_DATA = README COPYING LICENSE.AGPL LICENSE.BSD LICENSE.LGPL LICENSE.OpenSSL KNOWN_ISSUES USAGE

SUBDIRS = include src config plugins/dumper plugins/writer plugins/rater plugins/arpgraph tests

.PHONY: cscope doc clear

cscope:
	cd $(top_srcdir) && cscope -Rb $(CPPFLAGS)

distclean-local:
	rm -f cscope.out

clear:
	find $(top_srcdir) -type f -\( -name '*.c' -o -name '*.h' -\) | xargs sed -i -e 's/[ \t]\+$$//'

doc: Doxyfile
	doxygen $<
