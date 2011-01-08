#!/bin/sh
# Usage: sh -x ./autogen.sh

set -e

mkdir -p build-aux &&
libtoolize --force &&
aclocal &&
autoheader &&
automake --add-missing --foreign &&
autoconf &&
echo "Now run configure and make."
