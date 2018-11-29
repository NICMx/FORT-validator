AM_CFLAGS = -pedantic -Wall -std=gnu11 -I../src ${CHECK_CFLAGS}
MY_LDADD = ${CHECK_LIBS}

check_PROGRAMS = address.test line_file.test tal.test
TESTS = ${check_PROGRAMS}

address_test_SOURCES = address_test.c ../src/address.c ../src/address.h
address_test_LDADD = ${MY_LDADD}

line_file_test_SOURCES = line_file_test.c ../src/line_file.c ../src/line_file.h
line_file_test_LDADD = ${MY_LDADD}

tal_test_SOURCES = tal_test.c ../src/line_file.c ../src/line_file.h
tal_test_CFLAGS = ${AM_CFLAGS} ${GLIB_CFLAGS}
tal_test_LDADD = ${MY_LDADD} ${GLIB_LIBS}
