include $(top_srcdir)/scm2go.am

guilelibdir = @GUILELIBDIR@/srfi
SCM = srfi-43.scm
GOBJECTS = $(SCM:%.scm=%.go)

dist_guilelib_DATA = $(SCM) $(GOBJECTS)

distclean-local:
	@rm -f $(GOBJECTS)
