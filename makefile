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

install: release
	cp client/libdthread.so.0.1.0 /usr/local/lib/
	ln -s /usr/local/lib/libdthread.so.0.1.0 /usr/local/lib/libdthread.so.1
	ln -s /usr/local/lib/libdthread.so.1 /usr/local/lib/libdthread.so
	ldconfig
	mkdir -p /usr/local/include/dthread/
	cp client/src/main/dthread.h /usr/local/include/dthread/
	cp notes/interface.h /usr/local/include/dthread/
	cp server/dthreadd /usr/local/bin/

uninstall:
	rm /usr/local/lib/libdthread.so.0.1.0 /usr/local/lib/libdthread.so.1 /usr/local/lib/libdthread.so
	ldconfig
	rm -r /usr/local/include/dthread/
	rm /usr/local/bin/dthreadd