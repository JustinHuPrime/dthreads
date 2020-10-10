// Copyright 2020 Justin Hu
//
// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef DTHREADD_SODIUMALLOCATOR_H_
#define DTHREADD_SODIUMALLOCATOR_H_

#include <sodium.h>

#include <memory>
#include <string>

namespace dthreadd {
template <typename T>
struct SodiumAllocator : public std::allocator<T> {
  SodiumAllocator() noexcept = default;

  SodiumAllocator(SodiumAllocator const &) noexcept = default;

  template <typename U>
  SodiumAllocator(const std::allocator<U> &) noexcept {}

  ~SodiumAllocator() noexcept = default;

  T *allocate(std::size_t n) { return sodium_allocarray(n, sizeof(T)); }
  void deallocate(T *p, std::size_t n) { return sodium_free(p); }
};
}  // namespace dthreadd

#endif  // DTHREADD_SODIUMALLOCATOR_H_