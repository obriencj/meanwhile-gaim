
pkgdir = $(libdir)/gaim

pkg_LTLIBRARIES = libmwgaim.la

libmwgaim_la_SOURCES = mwgaim.c

libmwgaim_la_CFLAGS = \
	-Wall -Werror \
	$(GLIB_CFLAGS) $(GAIM_CFLAGS) $(MEANWHILE_CFLAGS)

libmwgaim_la_LDFLAGS = -module -avoid-version -no-undefined

#TODO remove -lmeanwhile when using meanwhile >= 0.4
libmwgaim_la_LIBADD = \
	$(GLIB_LIBS) $(GAIM_LIBS) \
	$(MEANWHILE_LIBS) -lmeanwhile

AM_CPPFLAGS = \
	-DG_LOG_DOMAIN=\"@PACKAGE@\" \
	-DGAIM_PLUGINS
