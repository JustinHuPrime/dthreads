// Copyright 2020 Justin Hu
//
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "jobFile.h"

#include <dlfcn.h>

#include <utility>

namespace dthreadd {
JobFile::JobFile() noexcept : handle(nullptr) {}
JobFile::JobFile(void *handle_) noexcept : handle(handle_) {}
JobFile::JobFile(JobFile &&other) noexcept : handle(other.handle) {
  other.handle = nullptr;
}
JobFile::~JobFile() noexcept {
  if (handle != nullptr) dlclose(handle);
}
JobFile &JobFile::operator=(JobFile &&other) noexcept {
  std::swap(other.handle, handle);
  return *this;
}
void *JobFile::get() const noexcept { return handle; }
}  // namespace dthreadd