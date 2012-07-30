guilelibdir = @GUILELIBDIR@/junkie/writer

include $(top_srcdir)/scm2go.am

SCM = capturer.scm

GOBJECTS = $(SCM:%.scm=%.go)

dist_guilelib_DATA = $(SCM) $(GOBJECTS)

distclean-local:
	@rm -f $(GOBJECTS)
