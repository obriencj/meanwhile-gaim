
pkg_LTLIBRARIES = libmwgaim.la

pkgdir = $(libdir)/gaim

libmwgaim_la_SOURCES = mwgaim.c

libmwgaim_la_CFLAGS = \
	-DPLUGIN_VERSION=\"@VERSION@\" \
	-DG_LOG_DOMAIN=\"@PACKAGE@\"

libmwgaim_la_LDFLAGS = -module -avoid-version

libmwgaim_la_LIBADD = $(GAIM_LIBS) $(MEANWHILE_LIBS) -lmeanwhile

INCLUDES = $(GLIB_CFLAGS) $(GAIM_CFLAGS) $(MEANWHILE_CFLAGS)

