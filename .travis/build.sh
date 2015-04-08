#!/bin/bash -x
# Make sure we exit if there is a failure
set -e

cd ${STEGOTORUS_HOME}
autoreconf -i
./configure --enable-silent-rules

make clean
make
RETURN="$?"


if [ "${RETURN}" != "0" ]; then
    echo "Building stegotorus failed!"
    exit 1
fi




