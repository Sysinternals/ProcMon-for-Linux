#!/bin/bash

# To make it easier for build and release pipelines to run apt-get,
# configure apt to not require confirmation (assume the -y argument by default)
DEBIAN_FRONTEND=noninteractive
echo "APT::Get::Assume-Yes \"true\";" > sudo /etc/apt/apt.conf.d/90assumeyes


sudo apt-get update
sudo apt -y install software-properties-common
sudo add-apt-repository "deb http://security.ubuntu.com/ubuntu xenial-security main"
sudo apt-get update

sudo apt remove -y clang-11

sudo apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        jq \
        git \
        fakeroot \
        gettext \
        wget \
        bison \
        build-essential \
        cmake \
        flex \
        libedit-dev \
        gcc-10 \
        libllvm6.0 \
        llvm-6.0-dev \
        libclang-6.0-dev \
        python \
        zlib1g-dev \
        libelf-dev \
        netperf \
        iperf \
        libfl-dev \
        liblocale-gettext-perl

# set clang preference
sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-12 100
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-10 100
gcc --version
clang --version

# install debbuild
wget https://github.com/debbuild/debbuild/releases/download/19.5.0/debbuild_19.5.0-ascherer.ubuntu18.04_all.deb \
    && sudo dpkg -i debbuild_19.5.0-ascherer.ubuntu18.04_all.deb

# install netcore 6 for signing process.
wget https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
rm packages-microsoft-prod.deb
sudo apt -y update && sudo apt-get install -y dotnet-runtime-6.0

# install bcc
git clone --branch v0.19.0 https://github.com/iovisor/bcc.git
mkdir -p bcc/build
cd bcc/build
sed -i 's/llvm-3\.7/llvm-6.0/g' ../CMakeLists.txt
cat ../CMakeLists.txt
cmake .. -DCMAKE_INSTALL_PREFIX=/usr -DLLVM_LIBRARY_DIRS=/usr/lib/llvm-6.0/lib
make
sudo make install