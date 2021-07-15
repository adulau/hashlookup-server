#!/bin/sh

git clone --recursive https://github.com/bitleak/kvrocks.git
cd kvrocks
git checkout 2.0
make -j4
