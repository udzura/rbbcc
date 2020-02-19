#!/bin/bash

# packages

install-package bison build-essential cmake flex git libedit-dev \
  libllvm6.0 llvm-6.0-dev libclang-6.0-dev python zlib1g-dev libelf-dev

sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 4052245BD4284CDD
echo "deb https://repo.iovisor.org/apt/$(lsb_release -cs) $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/iovisor.list
install-package --update-new libbcc

# build libbcc 0.11/0.12
ORIG_DIR=$(pwd)
sudo mkdir -p /opt/bcc

cd /
cache has_key libbcc-so && cache restore libbcc-so
cd -

if test "$(ls /opt/bcc | wc -l)" -le "0"; then
  mkdir -p /opt/bcc-work
  cd /opt/bcc-work
  git clone https://github.com/iovisor/bcc.git
  mkdir bcc/build
  cd bcc

  git checkout v0.11.0
  git submodule init
  git submodule sync
  git submodule update
  cd build
  cmake .. -DCMAKE_INSTALL_PREFIX=/opt/bcc
  make -j$(nproc)
  sudo make install
  make clean
  cd ..

  V0_12_HASH=2d099cd8c5cb1598d6e911c0b389132ebc7c101b
  git checkout $V0_12_HASH
  git submodule init
  git submodule sync
  git submodule update
  cd build
  cmake .. -DCMAKE_INSTALL_PREFIX=/opt/bcc
  make -j$(nproc)
  sudo make install

  # link all under /lib to /opt/bcc
  sudo ln -sf /opt/bcc/lib/libbcc.so.0.11.0 /opt/bcc/lib/libbcc.so.0.12.0 /usr/lib/x86_64-linux-gnu/

  cd /
  cache store libbcc-so opt/bcc
  cd -
fi
cd $ORIG_DIR

# Doing tests
set -e

bundle install --path vendor/bundle

bundle exec ruby -e "require 'rbbcc'; puts 'Using rbbcc: %s && libbcc: %s' % [RbBCC::VERSION, RbBCC::Clib.libbcc_version.to_s]"

sudo -E env PATH=$PATH bundle exec rake test
