// Copyright 2020 Justin Hu
//
// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef DTHREADD_JOBFILE_H_
#define DTHREADD_JOBFILE_H_

namespace dthreadd {
class JobFile {
 public:
  JobFile() noexcept;
  explicit JobFile(void *) noexcept;
  JobFile(JobFile const &) noexcept = delete;
  JobFile(JobFile &&) noexcept;

  ~JobFile() noexcept;

  JobFile &operator=(JobFile const &) noexcept = delete;
  JobFile &operator=(JobFile &&) noexcept;

  void *get() const noexcept;

 private:
  void *handle;
};
}  // namespace dthreadd

#endif  // DTHREADD_JOBFILE_H_