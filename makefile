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
	# library
	mkdir -p /usr/local/lib/
	cp client/libdthread.so.0.1.0 /usr/local/lib/
	ln -sf /usr/local/lib/libdthread.so.0.1.0 /usr/local/lib/libdthread.so.1
	ln -sf /usr/local/lib/libdthread.so.1 /usr/local/lib/libdthread.so
	ldconfig

	# includes
	mkdir -p /usr/local/include/dthread/
	cp client/src/main/dthread.h /usr/local/include/dthread/
	cp notes/interface.h /usr/local/include/dthread/

	# dthreadd
	mkdir -p /usr/local/bin/
	cp server/dthreadd /usr/local/bin/

	# manpages
	mkdir -p /usr/local/share/man/man1/
	mkdir -p /usr/local/share/man/man3/
	cp docs/dthreadd.1 /usr/local/share/man/man1/
	cp docs/dthread-job.3 docs/dthread.3 /usr/local/share/man/man3/

	# pkg-config
	mkdir -p /usr/local/lib/pkgconfig/
	cp docs/dthread.pc /usr/local/lib/pkgconfig/

uninstall:
  # library
	rm /usr/local/lib/libdthread.so.0.1.0 /usr/local/lib/libdthread.so.1 /usr/local/lib/libdthread.so
	ldconfig

	# includes
	rm -r /usr/local/include/dthread/

	# dthreadd
	rm /usr/local/bin/dthreadd

	# manpages
	rm /usr/local/share/man/man1/dthreadd.1
	rm /usr/local/share/man/man3/dthread.3 /usr/local/share/man/man3/dthread-job.3

	#pkg-config
	rm /usr/local/lib/pkgconfig/dthread.pc