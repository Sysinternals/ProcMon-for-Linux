# Process Monitor for Linux (Preview) [![Build Status](https://oss-sysinternals.visualstudio.com/Procmon%20for%20Linux/_apis/build/status/Sysinternals.ProcMon-for-Linux?branchName=main)](https://oss-sysinternals.visualstudio.com/Procmon%20for%20Linux/_build/latest?definitionId=20&branchName=main)
Process Monitor (Procmon) is a Linux reimagining of the classic Procmon tool from the Sysinternals suite of tools for Windows.  Procmon provides a convenient and efficient way for Linux developers to trace the syscall activity on the system.  

![Procmon in use](procmon.gif "Procmon in use")

# Installation & Usage

## Requirements
* OS: Ubuntu 18.04 lts 
* `cmake` >= 3.14 (build-time only)
* `libsqlite3-dev` >= 3.22 (build-time only)
 

## Install Procmon
Checkout our [install instructions](INSTALL.md) for distribution specific steps to install Procmon.

## Building Procmon from source


### 1. Install build dependencies
```bash
sudo apt-get -y install bison build-essential flex git libedit-dev \
  libllvm6.0 llvm-6.0-dev libclang-6.0-dev python zlib1g-dev libelf-dev
```

### 2. Build Procmon
```bash
git clone https://github.com/Microsoft/Procmon-for-Linux
cd Procmon-for-Linux
mkdir build
cd build
cmake ..
make
```

### Building Procmon Packages 
The distribution packages for Procmon for Linux are constructed utilizing `cpack`.

To build a `deb` package of Procmon on Ubuntu simply run:
```sh
cd build
cpack ..
```

## Usage
```
Usage: procmon [OPTIONS]
   OPTIONS
      -h/--help                Prints this help screen
      -p/--pids                Comma separated list of process ids to monitor
      -e/--events              Comma separated list of system calls to monitor
      -c/--collect [FILEPATH]  Option to start Procmon in a headless mode
      -f/--file FILEPATH       Open a Procmon trace file
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
The following traces process 20 only syscalls read, write and openat
```
sudo procmon -p 20 -e read,write,openat
```
The following traces process 35 and opens Procmon in headless mode to output all captured events to file procmon.db
```
sudo procmon -p 35 -c procmon.db
```
The following opens a Procmon tracefile, procmon.db, within the Procmon TUI
```
sudo procmon -f procmon.db
```

# Feedback
* Ask a question on Stack Overflow (tag with ProcmonForLinux)
* Request a new feature on GitHub
* Vote for popular feature requests
* File a bug in GitHub Issues

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
