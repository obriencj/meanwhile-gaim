
PRIVATE_PLUGIN = $(HOME)/.gaim/plugins
PRIVATE_PIXMAP = $(HOME)/.gaim/pixmaps/status/default

EXTRA_DIST = gaim-meanwhile.spec

SUBDIRS = src pixmaps dist

private-install:	all
	mkdir -p $(PRIVATE_PLUGIN) $(PRIVATE_PIXMAP)
	cp src/.libs/libmwgaim.so $(PRIVATE_PLUGIN)
	cp pixmaps/meanwhile.png $(PRIVATE_PIXMAP)

private-uninstall:
	rm -f $(PRIVATE_PLUGIN)/libmwgaim.so
	rm -f $(PRIVATE_PIXMAP)/meanwhile.png

