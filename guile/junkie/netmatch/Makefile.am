guilelibdir = @GUILELIBDIR@/junkie/netmatch

include $(top_srcdir)/scm2go.am

SCM = \
	netmatch.scm \
	ll-compiler.scm \
	types.scm \
	nettrack.scm

GOBJECTS = $(SCM:%.scm=%.go)

dist_guilelib_DATA = $(SCM) $(GOBJECTS)

distclean-local:
	@rm -f $(GOBJECTS)
