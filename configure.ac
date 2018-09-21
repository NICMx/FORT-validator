#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
# TODO change the bug report address
AC_INIT([rpki-validator], [0.0.1], [ydahhrk@gmail.com])
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
AC_SEARCH_LIBS([pthread_create], [pthread], [],
	[AC_MSG_ERROR([unable to find the pthread() function])]
)
AC_SEARCH_LIBS([ber_decode], [cmscodec], [],
	[AC_MSG_ERROR([unable to find the ber_decode() function])]
)

# Check dependencies.
#PKG_CHECK_MODULES([OPENSSL], [openssl])
PKG_CHECK_MODULES([CHECK], [check])

# Spit out the makefiles.
AC_OUTPUT(Makefile src/Makefile test/Makefile)
