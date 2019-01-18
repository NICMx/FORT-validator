AM_CFLAGS = -pedantic -Wall -std=gnu11 -I../src ${CHECK_CFLAGS}
MY_LDADD = ${CHECK_LIBS}

check_PROGRAMS = line_file.test tal.test rsync.test
TESTS = ${check_PROGRAMS}

line_file_test_SOURCES = ../src/file.c ../src/file.h ../src/log.c ../src/log.h
line_file_test_SOURCES += ../src/thread_var.c ../src/thread_var.h
line_file_test_SOURCES += ../src/common.c ../src/common.h
line_file_test_SOURCES += line_file_test.c ../src/line_file.c ../src/line_file.h
line_file_test_LDADD = ${MY_LDADD}

tal_test_SOURCES = ../src/file.c ../src/file.h ../src/log.c ../src/log.h
tal_test_SOURCES += ../src/thread_var.c ../src/thread_var.h
tal_test_SOURCES += ../src/common.c ../src/common.h
tal_test_SOURCES += ../src/crypto/base64.c ../src/crypto/base64.h
tal_test_SOURCES += tal_test.c ../src/line_file.c ../src/line_file.h
tal_test_CFLAGS = ${AM_CFLAGS} ${GLIB_CFLAGS}
tal_test_LDADD = ${MY_LDADD} ${GLIB_LIBS}

rsync_test_SOURCES = ../src/file.c ../src/file.h ../src/log.c ../src/log.h
rsync_test_SOURCES += ../src/thread_var.c ../src/thread_var.h
rsync_test_SOURCES += ../src/common.c ../src/common.h
rsync_test_SOURCES += rsync_test.c
rsync_test_LDADD = ${MY_LDADD}