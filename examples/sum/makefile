# Copyright 2020 Justin Hu
#
# SPDX-License-Identifier: LGPL-3.0-or-later

all: sum sumJob.so

.PHONY: clean

sum: sum.c
	gcc -g -o sum sum.c -I../../client/src/main/ -L../../client -l:libdthread.so.0.1.0

sumJob.so: sumJob.c
	gcc -shared -o sumJob.so sumJob.c

clean:
	rm sum sumJob.so