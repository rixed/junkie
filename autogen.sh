#!/bin/sh
# Usage: sh -x ./autogen.sh

set -e

mkdir -p build-aux &&
case `uname` in
  (Darwin*) glibtoolize --force ;;
  (*) libtoolize --force ;;
esac &&

if test -d /usr/local/share/aclocal; then
  aclocal -I /usr/local/share/aclocal
else
  aclocal
fi &&
autoheader &&
automake --add-missing --foreign &&
autoconf &&
echo "Now run configure and make."
