#!/bin/sh

if [[ ! ./kvrocks ]]
then
   git clone --recursive https://github.com/apache/incubator-kvrocks.git kvrocks
fi
cd kvrocks
git pull
git submodule update
#git checkout 2.0.1
#make -j4
mkdir build
./build.sh ./build
