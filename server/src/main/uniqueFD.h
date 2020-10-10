// Copyright 2020 Justin Hu
//
// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef DTHREADD_UNIQUEFD_H_
#define DTHREADD_UNIQUEFD_H_

namespace dthreadd {
class UniqueFD {
 public:
  UniqueFD() noexcept;
  explicit UniqueFD(int) noexcept;
  UniqueFD(UniqueFD const &) = delete;
  UniqueFD(UniqueFD &&) noexcept;

  ~UniqueFD() noexcept;

  UniqueFD &operator=(UniqueFD const &) = delete;
  UniqueFD &operator=(UniqueFD &&) noexcept;

  int get() const noexcept;

  void reset() noexcept;

 private:
  int fd;
};
}  // namespace dthreadd

#endif  // DTHREADD_UNIQUEFD_H_