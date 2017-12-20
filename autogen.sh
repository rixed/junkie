#!/bin/sh
# Usage: sh -x ./autogen.sh

set -e

mkdir -p build-aux &&
case `uname` in
  (Darwin*) glibtoolize --force ;;
  (*) libtoolize --force ;;
esac &&
aclocal &&
autoheader &&
automake --add-missing --foreign &&
autoconf &&
echo "Now run configure and make."
