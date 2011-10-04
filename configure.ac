AC_INIT([avalanche], [0.5.0])
AM_INIT_AUTOMAKE
AC_PROG_CXX
AC_PROG_CC
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SUBDIRS([valgrind stp-ver-0.1-11-18-2008])
AC_CONFIG_FILES([Makefile driver/Makefile agent/Makefile
                 driver/src/Makefile driver/include/Makefile
                 samples/Makefile samples/simple/Makefile])
AC_CONFIG_HEADER([av_config.h])

#----------------------------------------------------------------------------
# Needed in driver (as well as in valgrind)
#----------------------------------------------------------------------------
AC_ARG_WITH(tmpdir,
           [  --with-tmpdir=PATH      Specify path for temporary files],
              tmpdir="$withval",
                 tmpdir="/tmp")
AC_DEFINE_UNQUOTED(TMPDIR, "$tmpdir", [Temporary files directory])

AC_OUTPUT
