

STRIP=@STRIP@
PREFIX=@prefix@
VERSION=@VERSION@



nsis:
	$(STRIP) $(PREFIX)/lib/gaim/libmwgaim.dll
	$(STRIP) $(PREFIX)/bin/libmeanwhile-0.dll
	mkdir -p $(PREFIX)/dist 
	makensis /DPREFIX=$(PREFIX) /DVERSION=$(VERSION) meanwhile.nsi

