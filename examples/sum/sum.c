// Copyright 2020 Justin Hu
//
// SPDX-License-Identifier: LGPL-3.0-or-later

// sums numbers from 1 to 100 (inclusive) in blocks of 10 numbers at a time

#include <dthread/dthread.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
  int retval;

  DThreadPool pool;
  retval = dthreadInit(&pool);
  if (retval != 0) return -retval;

  retval = dthreadConnect(&pool, "127.0.0.1", 6474, "password", NULL);
  if (retval != 0) return -retval;

  retval = dthreadLoadFile(&pool, "sumJob.so", 1);
  if (retval != 0) return -retval;

  uint64_t local;
  DThreadJob *jobs[10];
  for (uint64_t start = 1; start <= 100; start += 10) {
    struct in {
      uint64_t from;
      uint64_t to;
    } in;
    in.from = start;
    in.to = start + 10;

    for (uint64_t i = in.from; i < in.to; i++) local += i;

    retval = dthreadStart(&pool, 1, &in, sizeof(struct in), &jobs[start / 10]);
    if (retval != 0) return -retval;
  }

  uint64_t acc;
  for (size_t idx = 0; idx < 10; idx++) {
    void *outBuffer;
    retval = dthreadJoin(jobs[idx], &outBuffer, NULL);
    if (retval != 0) return -retval;

    uint64_t *out = outBuffer;
    acc += *out;
    free(outBuffer);
  }

  dthreadUninit(&pool);

  printf("Computed: %lu, actual: %lu\n", acc, local);

  return EXIT_SUCCESS;
}