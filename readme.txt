#!/bin/bash
# must enable version 9 toolset that was installed via (as root):
#  yum install devtoolset-9
#
scl enable devtoolset-9 bash

# build with build script
./build.sh
