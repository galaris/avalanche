AC_INIT(stp, 0.1)
AM_INIT_AUTOMAKE
AC_PROG_CXX
AC_PROG_RANLIB
AC_PROG_LEX
AC_PROG_YACC
AC_CONFIG_MACRO_DIR([m4])
AC_CHECK_PROG(PERL, perl, perl)
AC_LANG(C++)
AC_CHECK_HEADERS([ext/hash_map ext/hash_set hash_map hash_set])
AC_CONFIG_HEADER(config.h)
AC_CONFIG_FILES([Makefile AST/Makefile sat/Makefile sat/core/Makefile
                 sat/mtl/Makefile simplifier/Makefile bitvec/Makefile
                 c_interface/Makefile constantbv/Makefile parser/Makefile])
AC_OUTPUT
