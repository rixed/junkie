guilelibdir = @GUILELIBDIR@/junkie/netmatch

include $(top_srcdir)/scm2go.am

SCM = \
	netmatch.scm \
	ll-compiler.scm \
	types.scm \
	nettrack.scm

GOBJECTS = $(SCM:%.scm=%.go)

dist_guilelib_DATA = $(SCM)

guilecachedir = @GUILECACHEDIR@/junkie/netmatch
dist_guilecache_DATA = $(GOBJECTS)

install_go_files = install-dist_guilecacheDATA
$(install_go_files): install-dist_guilelibDATA

distclean-local:
	@rm -f $(GOBJECTS)
