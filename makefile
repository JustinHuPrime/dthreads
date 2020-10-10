# Copyright 2020 Justin Hu
#
# SPDX-License-Identifier: LGPL-3.0-or-later

.PHONY: debug release clean install uninstall

debug:
	$(MAKE) debug -C server
	$(MAKE) debug -C client

release: clean
	$(MAKE) release -C server
	$(MAKE) release -C client

clean:
	$(MAKE) clean -C server
	$(MAKE) clean -C client

install:
	mkdir -p /usr/local/lib/
	cp client/libdthread.so.0.1.0 /usr/local/lib/
	ln -sf /usr/local/lib/libdthread.so.0.1.0 /usr/local/lib/libdthread.so.1
	ln -sf /usr/local/lib/libdthread.so.1 /usr/local/lib/libdthread.so
	ldconfig
	mkdir -p /usr/local/include/dthread/
	cp client/src/main/dthread.h /usr/local/include/dthread/
	cp notes/interface.h /usr/local/include/dthread/
	mkdir -p /usr/local/bin/
	cp server/dthreadd /usr/local/bin/
	mkdir -p /usr/local/share/man/man1/
	mkdir -p /usr/local/share/man/man3/
	cp docs/dthreadd.1 /usr/local/share/man/man1/
	cp docs/dthread-job.3 docs/dthread.3 /usr/local/share/man/man3/

uninstall:
	rm /usr/local/lib/libdthread.so.0.1.0 /usr/local/lib/libdthread.so.1 /usr/local/lib/libdthread.so
	ldconfig
	rm -r /usr/local/include/dthread/
	rm /usr/local/bin/dthreadd
	rm /usr/local/share/man/man1/dthreadd.1
	rm /usr/local/share/man/man3/dthread.3 /usr/local/share/man/man3/dthread-job.3