dnl Process this file with autoconf to produce a configure script.

AC_INIT([xhydra],[0.1])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

AC_PROG_CC

pkg_modules="gtk+-3.0 >= 3.24.24"
PKG_CHECK_MODULES(PACKAGE, [$pkg_modules])
AC_SUBST(PACKAGE_CFLAGS)
AC_SUBST(PACKAGE_LIBS)

AC_CONFIG_FILES([
Makefile
src/Makefile
])
AC_OUTPUT
