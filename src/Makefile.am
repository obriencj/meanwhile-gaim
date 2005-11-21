
pkgdir = $(_libdir)/gaim

pkg_LTLIBRARIES = libmwgaim.la

noinst_HEADERS = \
	mime.h


libmwgaim_la_SOURCES = \
	config.h \
	mwgaim.c \
	mime.c

libmwgaim_la_CFLAGS = \
	$(DEBUG_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(GAIM_CFLAGS) $(MEANWHILE_CFLAGS)

libmwgaim_la_LDFLAGS = \
	-module -avoid-version -no-undefined

libmwgaim_la_LIBADD = \
	$(GLIB_LIBS) $(GAIM_LIBS)

if MEANWHILE_STATIC
libmwgaim_la_LIBADD += $(MEANWHILE_LIBA)
else
libmwgaim_la_LIBADD += $(MEANWHILE_LIBS)
endif

AM_CPPFLAGS = \
	-DG_LOG_DOMAIN=\"@PACKAGE@\" \
	-DGAIM_PLUGINS
