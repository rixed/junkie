guilelibdir = @GUILELIBDIR@/junkie/writer

include $(top_srcdir)/scm2go.am

SCM = capturer.scm

GOBJECTS = $(SCM:%.scm=%.go)

dist_guilelib_DATA = $(SCM)

guilecachedir = @GUILECACHEDIR@/junkie/writer
dist_guilecache_DATA = $(GOBJECTS)

install_go_files = install-dist_guilecacheDATA
$(install_go_files): install-dist_guilelibDATA

distclean-local:
	@rm -f $(GOBJECTS)
