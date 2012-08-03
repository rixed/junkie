SUBDIRS = static_files

include $(top_srcdir)/scm2go.am

guilelibdir = @GUILELIBDIR@/junkie/www

SCM = \
	crud.scm \
	monitor.scm \
	server.scm

GOBJECTS = $(SCM:%.scm=%.go)

dist_guilelib_DATA = $(SCM)

guilecachedir = @GUILECACHEDIR@/junkie/www
dist_guilecache_DATA = $(GOBJECTS)

install_go_files = install-dist_guilecacheDATA
$(install_go_files): install-dist_guilelibDATA

distclean-local:
	@rm -f $(GOBJECTS)
