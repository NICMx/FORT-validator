#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([fort], [1.2.1], [fort-validator@nic.mx])
AC_CONFIG_SRCDIR([src/main.c])
AM_INIT_AUTOMAKE([subdir-objects])

# Checks for programs.
AC_PROG_CC

# Create src/configure_ac.h, put some useful macros there.
AC_CONFIG_HEADERS([src/configure_ac.h])

# Checks for header files.
AC_CHECK_HEADERS([netinet/in.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_CHECK_HEADER_STDBOOL

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset socket])
AC_SEARCH_LIBS([pthread_create], [pthread], [],
	[AC_MSG_ERROR([unable to find the pthread() function])]
)
AC_SEARCH_LIBS([X509_get_version], [crypto], [],
	[AC_MSG_ERROR([unable to find the X509_get_version() function])]
)
AC_SEARCH_LIBS([backtrace],[execinfo],[],
	[AC_MSG_ERROR([unable to find backtrace() function])]
)

# Dependencies managed by pkg-config
# By the way: Apparently PKG_CHECK_MODULES is poor practice now. I can't tell;
# it's always the same guy complaining about it in Stack Overflow.
# (Main one: https://stackoverflow.com/questions/10220946)
# But I couldn't make check work with AC_SEARCH_LIBS, and (probably due to
# typical obscure bullshit autotools reasoning) I have no idea why.
PKG_CHECK_MODULES([JANSSON], [jansson])
PKG_CHECK_MODULES([CURL], [libcurl])
PKG_CHECK_MODULES([XML2], [libxml-2.0])
PKG_CHECK_MODULES([CHECK], [check], [usetests=yes], [usetests=no])
AM_CONDITIONAL([USE_TESTS], [test "x$usetests" = "xyes"])

# Spit out the makefiles.
AC_OUTPUT(Makefile src/Makefile man/Makefile test/Makefile)
