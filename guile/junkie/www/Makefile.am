SUBDIRS = static_files

include $(top_srcdir)/scm2go.am

guilelibdir = @GUILELIBDIR@/junkie/www

SCM = \
	crud.scm \
	monitor.scm \
	server.scm

GOBJECTS = $(SCM:%.scm=%.go)

dist_guilelib_DATA = $(SCM) $(GOBJECTS)

distclean-local:
	@rm -f $(GOBJECTS)
