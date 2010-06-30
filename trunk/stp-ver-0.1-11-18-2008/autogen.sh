#!/bin/sh

set -ex

aclocal
autoheader
libtoolize --force --copy
autoconf
automake --add-missing --copy --foreign
