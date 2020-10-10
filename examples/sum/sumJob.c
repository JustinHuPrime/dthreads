// Copyright 2020 Justin Hu
//
// SPDX-License-Identifier: LGPL-3.0-or-later

#include <stdint.h>

struct in {
  uint64_t from;
  uint64_t to;
};

uint32_t const jobInLen = sizeof(struct in);
uint32_t const jobOutLen = sizeof(uint64_t);

void job(void *inBuffer, void *outBuffer) {
  struct in in = *(struct in *)inBuffer;
  uint64_t *out = outBuffer;

  uint64_t acc = 0;
  for (uint64_t i = in.from; i < in.to; i++) {
    acc += i;
  }

  *out = acc;
}