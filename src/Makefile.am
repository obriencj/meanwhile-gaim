
pkg_LTLIBRARIES = libmwgaim.la

pkgdir = $(libdir)/gaim

libmwgaim_la_SOURCES = mwgaim.c

libmwgaim_la_CFLAGS = \
	-DPLUGIN_VERSION=\"@VERSION@\" \
	-DG_LOG_DOMAIN=\"@PACKAGE@\"

libmwgaim_la_LDFLAGS = -module -avoid-version -no-undefined

#TODO remove -lmeanwhile
libmwgaim_la_LIBADD = $(GLIB_LIBS) $(GAIM_LIBS) $(MEANWHILE_LIBS) -lmeanwhile $(WIN32_LIBS)

INCLUDES = $(GLIB_CFLAGS) $(GAIM_CFLAGS) $(MEANWHILE_CFLAGS)

