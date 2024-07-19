#!/bin/bash

# To make it easier for build and release pipelines to run apt-get,
# configure apt to not require confirmation (assume the -y argument by default)
DEBIAN_FRONTEND=noninteractive
echo "APT::Get::Assume-Yes \"true\";" > /etc/apt/apt.conf.d/90assumeyes

sudo apt-get update
sudo apt -y install software-properties-common
sudo add-apt-repository "deb http://security.ubuntu.com/ubuntu xenial-security main"
sudo apt-get update

sudo apt upgrade -y \
    && sudo apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        g++ \
        make \
        cmake \
        libelf-dev \
        llvm \
        clang \
        libxml2 \
        libxml2-dev \
        libzstd1 \
        git \
        libgtest-dev \
        apt-transport-https \
        dirmngr \
        libjson-glib-dev \
        libc6-dev-i386 \
        libssl-dev \
        gettext \
        libbpf-dev

sudo wget https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/openat2.h -O /usr/include/linux/openat2.h

# install debbuild
wget https://github.com/debbuild/debbuild/releases/download/19.5.0/debbuild_19.5.0-ascherer.ubuntu18.04_all.deb \
    && sudo dpkg -i debbuild_19.5.0-ascherer.ubuntu18.04_all.deb
