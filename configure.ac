#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
# TODO change the bug report address
AC_INIT([rtr-server], [0.0.1], [ydahhrk@gmail.com])
AC_CONFIG_SRCDIR([src/main.c])
AM_INIT_AUTOMAKE([subdir-objects])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([netinet/in.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_CHECK_HEADER_STDBOOL

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset socket])
AC_SEARCH_LIBS([pthread_create], [pthread])

# Uhhh... this one starts with "PKG_" so it's probably different.
# No idea.
PKG_CHECK_MODULES([CHECK], [check])
PKG_CHECK_MODULES([JANSSON], [jansson])

# Spit out the makefiles.
AC_OUTPUT(Makefile src/Makefile man/Makefile test/Makefile)
