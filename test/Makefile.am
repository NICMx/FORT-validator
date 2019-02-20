# Reminder: `make check`

# If you want to only run one test, do `make check TESTS=<test>`.
# Example: `make check TESTS=address`

# Once compiled, you can also just run the test directly: `./address.test`
# You can easily see standard output and error this way.

AM_CFLAGS = -pedantic -Wall -std=gnu11 -I../src -DUNIT_TESTING ${CHECK_CFLAGS}
MY_LDADD = ${CHECK_LIBS}
BASIC_MODULES  = ../src/config.c ../src/config.h
BASIC_MODULES += ../src/log.c ../src/log.h
BASIC_MODULES += impersonator.c

check_PROGRAMS  = address.test
check_PROGRAMS += vcard.test
check_PROGRAMS += line_file.test
check_PROGRAMS += rsync.test
check_PROGRAMS += tal.test
TESTS = ${check_PROGRAMS}

address_test_SOURCES  = ${BASIC_MODULES}
address_test_SOURCES += ../src/address.h
address_test_SOURCES += address_test.c
address_test_LDADD = ${MY_LDADD}

vcard_test_SOURCES  = ${BASIC_MODULES}
vcard_test_SOURCES += vcard_test.c
vcard_test_LDADD = ${MY_LDADD}

line_file_test_SOURCES  = ${BASIC_MODULES}
line_file_test_SOURCES += ../src/file.c ../src/file.h
line_file_test_SOURCES += ../src/line_file.c ../src/line_file.h
line_file_test_SOURCES += line_file_test.c
line_file_test_LDADD = ${MY_LDADD}

rsync_test_SOURCES  = ${BASIC_MODULES}
rsync_test_SOURCES += ../src/common.c ../src/common.h
rsync_test_SOURCES += ../src/uri.c ../src/uri.h
rsync_test_SOURCES += rsync_test.c
rsync_test_LDADD = ${MY_LDADD}

tal_test_SOURCES  = ${BASIC_MODULES}
tal_test_SOURCES += ../src/file.c ../src/file.h
tal_test_SOURCES += ../src/common.c ../src/common.h
tal_test_SOURCES += ../src/crypto/base64.c ../src/crypto/base64.h
tal_test_SOURCES += ../src/random.c ../src/random.h
tal_test_SOURCES += ../src/uri.c ../src/uri.h
tal_test_SOURCES += ../src/line_file.c ../src/line_file.h
tal_test_SOURCES += tal_test.c
tal_test_CFLAGS = ${AM_CFLAGS}
tal_test_LDADD = ${MY_LDADD}
