
all: killfd

killfd: killfd.c
	gcc killfd.c -o killfd

install: all
	mkdir -p $(DESTDIR)/usr/bin
	cp killfd $(DESTDIR)/usr/bin/
