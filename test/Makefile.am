# Reminder: `make check`

# If you want to only run one test, do `make check TESTS=<test>`.
# Example: `make check TESTS=address`

# Once compiled, you can also just run the test directly: `./address.test`
# You can easily see standard output and error this way.

AM_CFLAGS = -pedantic -Wall -std=gnu11 -I../src -DUNIT_TESTING ${CHECK_CFLAGS}
MY_LDADD = ${CHECK_LIBS}

check_PROGRAMS = address.test line_file.test rsync.test tal.test
TESTS = ${check_PROGRAMS}

address_test_SOURCES = ../src/address.h
address_test_SOURCES += ../src/log.c ../src/log.h
address_test_SOURCES += address_test.c
address_test_LDADD = ${MY_LDADD}

line_file_test_SOURCES = ../src/file.c ../src/file.h ../src/log.c ../src/log.h
line_file_test_SOURCES += ../src/common.c ../src/common.h
line_file_test_SOURCES += line_file_test.c ../src/line_file.c ../src/line_file.h
line_file_test_LDADD = ${MY_LDADD}

tal_test_SOURCES = ../src/file.c ../src/file.h ../src/log.c ../src/log.h
tal_test_SOURCES += ../src/config.c ../src/config.h
tal_test_SOURCES += ../src/toml_handler.c ../src/toml_handler.h
tal_test_SOURCES += ../src/common.c ../src/common.h
tal_test_SOURCES += ../src/crypto/base64.c ../src/crypto/base64.h
tal_test_SOURCES += ../src/random.c ../src/random.h
tal_test_SOURCES += ../src/uri.c ../src/uri.h
tal_test_SOURCES += tal_test.c ../src/line_file.c ../src/line_file.h
tal_test_CFLAGS = ${AM_CFLAGS} ${GLIB_CFLAGS}
tal_test_LDADD = ${MY_LDADD} ${GLIB_LIBS}

rsync_test_SOURCES = ../src/file.c ../src/file.h ../src/log.c ../src/log.h
rsync_test_SOURCES += ../src/config.c ../src/config.h
rsync_test_SOURCES += ../src/toml_handler.c ../src/toml_handler.h
rsync_test_SOURCES += ../src/uri.c ../src/uri.h
rsync_test_SOURCES += ../src/common.c ../src/common.h
rsync_test_SOURCES += rsync_test.c
rsync_test_LDADD = ${MY_LDADD}
