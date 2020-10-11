# DThreads

Distributed computing using a pthread-like interface.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Support](#support)
- [Contributing](#contributing)
- [License](#license)

## Installation

To install, download the package, and run `make release`, then `make install` as root.

## Usage

Use `libdthread` in clients to send jobs to servers.

Run `dthreadd` (requires interactive input on startup) to act as a job server. Warning: this allows anyone with the server's password to remotely execute code!

## Support

Please [open an issue](https://github.com/JustinHuPrime/dthreads/issues) if you find bugs or improvements.

## Contributing

Please contribute using [Github Flow](https://guides.github.com/introduction/flow/). Create a branch, add commits, and [open a pull request](https://github.com/fraction/readme-boilerplate/compare/).

## License

Copyright 2020 Justin Hu.
License LGPLv3+: GNU Lesser GPL version 3 or later <https://gnu.org/licenses/lgpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
