#!/bin/sh

git clone --recursive https://github.com/KvrocksLabs/kvrocks.git
cd kvrocks
git checkout 2.0.1
make -j4
