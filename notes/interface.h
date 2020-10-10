// Copyright 2020 Justin Hu
//
// SPDX-License-Identifier: LGPL-3.0-or-later

// all shared object files used by dthread are expected to support the following
// interface:

#include <stdint.h>

extern uint32_t const jobInLen;
extern uint32_t const jobOutLen;

void job(void *, void *);