#!/bin/bash -x
# Make sure we exit if there is a failure
set -e

autoreconf -i
./configure --enable-silent-rules

make clean
make
RETURN="$?"


if [ "${RETURN}" != "0" ]; then
    echo "Building jel failed!"
    exit 1
fi




