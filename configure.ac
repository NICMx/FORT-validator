#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
# TODO change the bug report address
AC_INIT([fort], [0.0.1], [ydahhrk@gmail.com])
AC_CONFIG_SRCDIR([src/main.c])
AM_INIT_AUTOMAKE([subdir-objects])

# Checks for programs.
AC_PROG_CC

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
AC_SEARCH_LIBS([d2i_X509_bio], [crypto], [],
	[AC_MSG_ERROR([unable to find the d2i_X509_bio() function])]
)
AC_SEARCH_LIBS([backtrace],[execinfo],[],
	[AC_MSG_ERROR([unable to find backtrace() function])]
)

# Dependencies managed by pkg-config

PKG_CHECK_MODULES([JANSSON], [jansson])

# By the way: Apparently PKG_CHECK_MODULES is poor practice now. I can't tell;
# it's always the same guy complaining about it in Stack Overflow.
# (Main one: https://stackoverflow.com/questions/10220946)
# But I couldn't make check work with AC_SEARCH_LIBS, and (probably due to
# typical obscure bullshit autotools reasoning) I have no idea why.

AC_ARG_WITH(
	[unit-tests],
	AS_HELP_STRING(
		[--with-unit-tests],
		[Generate unit tests. (Requires check)]
	)
)

# https://www.gnu.org/software/automake/manual/html_node/Conditional-Subdirectories.html
# "Subdirectories with AM_CONDITIONAL" never worked for me. The problem might
# be that it puts `MAYBE_TESTS` in `.PRECIOUS`, which maybe is a bug in the
# autotools. (I honestly can't tell. They are so incredibly poorly designed.)
# The code below is implemented as "Subdirectories with AC_SUBST."
if test "x$with_unit_tests" = "xyes"; then
	PKG_CHECK_MODULES([CHECK], [check])
	MAYBE_TESTS=test
else
	MAYBE_TESTS=
fi
AC_SUBST([MAYBE_TESTS])

# Spit out the makefiles.
AC_OUTPUT(Makefile src/Makefile man/Makefile test/Makefile)
