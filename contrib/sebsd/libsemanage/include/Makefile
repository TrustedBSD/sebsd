# Installation directories.
PREFIX ?= $(DESTDIR)/usr
INCDIR ?= $(PREFIX)/include/semanage

install:
	test -d $(INCDIR) || install -m 755 -d $(INCDIR)
	install -m 644 $(wildcard semanage/*.h) $(INCDIR)

indent:
	../../Lindent $(wildcard semanage/*.h)
