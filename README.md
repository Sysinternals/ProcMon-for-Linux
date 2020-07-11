# Procmon 
Procmon is a Linux reimagining of the classic Procmon tool from the Sysinternals suite of tools for Windows.  Procmon provides a convenient and efficient way for Linux developers to trace the syscall activity on the system. 

![Procmon in use](procmon.gif "Procmon in use")
## Install Procmon
Checkout our [install instructions](INSTALL.md) for ditribution specific steps to install Procmon.

## Building from source

### Build-time deps
* `cmake` >= 3.13
* `libsqlite3-dev` >= 3.22

```bash
sudo apt-get -y install bison build-essential flex git libedit-dev \
  libllvm6.0 llvm-6.0-dev libclang-6.0-dev python zlib1g-dev libelf-dev
```

### Building

#### 1. Build BCC
```bash
git clone --branch tag_v0.10.0 https://github.com/iovisor/bcc.git
mkdir bcc/build
cd bcc/build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr
make
sudo make install
```

#### 2. Build Procmon
```bash
git clone https://github.com/Microsoft/Procmon-for-Linux
cd procmon-for-linux
mkdir build
cd build
cmake ..
make
```

### Building Procmon Packages 
The distribution packages for Procmon for Linux are constructed utilizing `debbuild` for Debian targets and `rpmbuild` for Fedora targets.

To build a `deb` package of Procmon on Ubuntu simply run:
```sh
make && make deb
```

To build a `rpm` package of Procmon on Fedora simply run:
```sh
make && make rpm
```

## Usage
```
Usage: procmon [OPTIONS]
   OPTIONS
      -h/--help            Prints this help screen
      -p/--pids            Comma separated list of process ids to monitor
```

### Examples
The following traces all processes and syscalls on the system
```
sudo procmon
```
The following traces processes with process id 10 and 20
```
sudo procmon -p 10,20
```

# Contributing
If you are interested in fixing issues and contributing directly to the code base, please see the [document How to Contribute](CONTRIBUTING.md), which covers the following:
* How to build and run from source
* The development workflow, including debugging and running tests
* Coding Guidelines
* Submitting pull requests

Please see also our [Code of Conduct](CODE_OF_CONDUCT.md).


# License
Copyright (c) Microsoft Corporation. All rights reserved.

Licensed under the MIT License.