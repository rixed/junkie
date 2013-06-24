AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

dist_doc_DATA = README.md NEWS COPYING LICENSE.AGPL LICENSE.BSD LICENSE.LGPL LICENSE.OpenSSL KNOWN_ISSUES USAGE

SUBDIRS = \
	include \
	src \
	config \
	plugins/dumper \
	plugins/writer \
	plugins/rater \
	plugins/arpgraph \
	plugins/serializer \
	plugins/os-detect \
	plugins/packetogram \
	plugins/duplicogram \
	plugins/nettop \
	guile \
	tests \
	doc

.PHONY: cscope doc clear module-deps

EXTRA_DIST = .tarball-version
.tarball-version:
	echo "$(VERSION)" > $@

cscope:
	cd $(top_srcdir) && cscope -Rb $(filter -I%, $(CPPFLAGS))

distclean-local:
	rm -f cscope.out .tarball-version module-deps.dot

clear:
	find $(top_srcdir) -type f -\( -name '*.c' -o -name '*.h' -o -name '*.scm' -\) | xargs sed -i -e 's/[ \t]\+$$//'

doc: Doxyfile
	doxygen $<
	$(MAKE) -C doc $@

module-deps.dot:
	@(echo "digraph deps {" ;\
	 find $(top_srcdir)/src -type f -name '*.c' |\
	 while read f ; do grep '_init()' $$f |\
	   sed -e 's|^[ \t]*\(\<.*\)_init();.*$$|\1|g' |\
	   grep -v _ |\
	   while read g ; do \
	     ff=$$(basename $$f .c) ;\
	     echo "$$ff -> $$g" ;\
	   done ;\
	 done ;\
	 echo "}") > $@

module-deps: module-deps.dot
	@$(top_srcdir)/find_cycles

setcap:
	setcap cap_net_raw,cap_net_admin=eip $(bindir)/junkie

