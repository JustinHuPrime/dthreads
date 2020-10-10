# Copyright 2020 Justin Hu
#
# SPDX-License-Identifier: LGPL-3.0-or-later

.PHONY: all clean

all: sum sumJob.so

sum: sum.c
	gcc -g -o sum sum.c -I/usr/local/include/dthread -ldthread

sumJob.so: sumJob.c
	gcc -shared -o sumJob.so sumJob.c

clean:
	rm sum sumJob.so