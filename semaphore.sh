#!/bin/bash

sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 4052245BD4284CDD
echo "deb https://repo.iovisor.org/apt/$(lsb_release -cs) $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install libbcc

bundle install --path vendor/bundle

bundle exec ruby -e "require 'rbbcc'; puts RbBCC::VERSION"

sudo chmod u+s `bundle which ruby`

bundle exec rake test
