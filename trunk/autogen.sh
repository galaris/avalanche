#!/bin/sh -x

aclocal
libtoolize --force --copy
autoconf
automake --add-missing --copy --foreign

(cd valgrind; ./autogen.sh)
