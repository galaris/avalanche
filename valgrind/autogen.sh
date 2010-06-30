#!/bin/sh

set -ex

aclocal
autoheader
automake -a
autoconf
