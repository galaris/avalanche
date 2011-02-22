#!/bin/sh -x

set -ex
aclocal
libtoolize --force --copy
autoconf
automake --add-missing --copy --foreign

(cd valgrind; ./autogen.sh)
(cd stp-ver-0.1-11-18-2008; ./autogen.sh)
