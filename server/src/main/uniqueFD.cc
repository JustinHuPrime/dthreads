// Copyright 2020 Justin Hu
//
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "uniqueFD.h"

#include <unistd.h>

#include <utility>

namespace dthreadd {
UniqueFD::UniqueFD() noexcept : UniqueFD(-1) {}
UniqueFD::UniqueFD(int fd_) noexcept : fd(fd_) {}
UniqueFD::UniqueFD(UniqueFD &&other) noexcept : fd(other.fd) { other.fd = -1; }
UniqueFD ::~UniqueFD() noexcept { reset(); }
UniqueFD &UniqueFD::operator=(UniqueFD &&other) noexcept {
  std::swap(fd, other.fd);
  return *this;
}
int UniqueFD::get() const noexcept { return fd; }
void UniqueFD::reset() noexcept {
  if (fd != -1) {
    close(fd);
    fd = -1;
  }
}
}  // namespace dthreadd