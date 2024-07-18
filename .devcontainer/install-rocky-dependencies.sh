#!/bin/bash

# install all needed packges to build .rpm packages
echo "assumeyes=1" >> /etc/yum.conf

# install endpoint for git > 2.0
yum install http://opensource.wandisco.com/rhel/8/git/x86_64/wandisco-git-release-8-1.noarch.rpm

# Enable powertools and extra repos
dnf install dnf-plugins-core && dnf install epel-release && dnf config-manager --set-enabled powertools && dnf update

yum update \
    && yum install \
       gcc \
       gcc-c++ \
       make \
       cmake \
       llvm \
       clang \
       elfutils-libelf-devel \
       rpm-build \
       json-glib-devel \
       python3 \
       libxml2-devel \
       glibc-devel.i686 \
       openssl-devel \
       ncurses-devel
