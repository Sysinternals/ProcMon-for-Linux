# Contributing

Before we can accept a pull request from you, you'll need to sign a [Contributor License Agreement (CLA)](https://cla.microsoft.com). It is an automated process and you only need to do it once.
To enable us to quickly review and accept your pull requests, always create one pull request per issue and link the issue in the pull request. Never merge multiple requests in one unless they have the same root cause. Be sure to follow our Coding Guidelines and keep code changes as small as possible. Avoid pure formatting changes to code that has not been modified otherwise. Pull requests should contain tests whenever possible.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

# Branching
The main branch contains current development.  While CI should ensure that main always builds, it is still considered pre-release code.  Release checkpoints will be put into stable branches for maintenance.

To contribute, fork the repository and create a branch in your fork for your work.  Please keep branch names short and descriptive.  Please direct PRs into the upstream main branch.

## Build and run from source
### Environment
* `Linux` OS (dev team is using Ubuntu 18.04)
  * Development can be done on Windows Subsystem for Linux, but Procmon cannot be executed in that environment
* `git`
* `cmake` >= 3.14
* `libsqlite3-dev` >= 3.22

```bash
sudo apt-get -y install bison build-essential flex git libedit-dev \
  libllvm6.0 llvm-6.0-dev libclang-6.0-dev python zlib1g-dev libelf-dev
```

##### 1. Build BCC
```bash
git clone --branch tag_v0.10.0 https://github.com/iovisor/bcc.git
mkdir bcc/build
cd bcc/build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr
make
sudo make install
```

##### 2. Build Procmon
```bash
git clone https://github.com/microsoft/Procmon-for-Linux
cd procmon-for-linux
mkdir build
cd build
cmake ..
make
```

## Pull Requests
* Always tag a work item or issue with a pull request.
* Limit pull requests to as few issues as possible, preferably 1 per PR

