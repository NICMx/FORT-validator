# Reminder: Automake will automatically add this to any targets where
# <mumble>_CFLAGS is not defined.
# Otherwise it must be included manually:
# 	mumble_mumble_CFLAGS = $(AM_CFLAGS) flag1 flag2 flag3 ...
AM_CFLAGS = -pedantic -Wall -std=gnu11 -I../src @CHECK_CFLAGS@

# Reminder: As opposed to AM_CFLAGS, "AM_LDADD" is not idiomatic automake, and
# autotools will even reprehend us if we declare it. Therefore, I came up with
# "my" own "ldadd". Unlike AM_CFLAGS, it needs to be manually added to every
# target.
MY_LDADD = $(CHECK_LIBS)

check_PROGRAMS = rtr/primitive_reader.test rtr/pdu.test address.test
TESTS = $(check_PROGRAMS)

rtr_primitive_reader_test_SOURCES = \
	rtr/primitive_reader_test.c \
	rtr/stream.c
rtr_primitive_reader_test_LDADD = $(MY_LDADD)

rtr_pdu_test_SOURCES = \
	rtr/pdu_test.c \
	rtr/stream.c \
	$(top_builddir)/src/rtr/primitive_reader.c \
	$(top_builddir)/src/rtr/pdu_handler.c
rtr_pdu_test_LDADD = $(MY_LDADD)

address_test_SOURCES = ../src/address.h
address_test_SOURCES += address_test.c
address_test_LDADD = $(MY_LDADD)
