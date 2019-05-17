# Reminder: `make check`
# Your `./configure` needs to have included the `--with-unit-tests` flag.

# If you want to only run one test, do `make check TESTS=<test>`.
# Example: `make check TESTS=address`

# Once compiled, you can also just run the test directly: `./address.test`
# You can easily see standard output and error this way.

# Reminder: Automake will automatically add this to any targets where
# <mumble>_CFLAGS is not defined.
# Otherwise it must be included manually:
# 	mumble_mumble_CFLAGS = ${AM_CFLAGS} flag1 flag2 flag3 ...
AM_CFLAGS = -pedantic -Wall -std=gnu11 -I../src -DUNIT_TESTING ${CHECK_CFLAGS}
# Reminder: As opposed to AM_CFLAGS, "AM_LDADD" is not idiomatic automake, and
# autotools will even reprehend us if we declare it. Therefore, I came up with
# "my" own "ldadd". Unlike AM_CFLAGS, it needs to be manually added to every
# target.
MY_LDADD = ${CHECK_LIBS}
BASIC_MODULES  = ../src/log.c ../src/log.h
BASIC_MODULES += impersonator.c

SLURM_SOURCES  = ../src/address.c ../src/address.h
SLURM_SOURCES += ../src/json_parser.c ../src/json_parser.h
SLURM_SOURCES += ../src/crypto/base64.c ../src/crypto/base64.h
SLURM_SOURCES += ../src/slurm/slurm_db.c ../src/slurm/slurm_db.h
SLURM_SOURCES += ../src/slurm/slurm_loader.c
SLURM_SOURCES += ../src/slurm/slurm_loader.h
SLURM_SOURCES += ../src/slurm/slurm_parser.c
SLURM_SOURCES += ../src/slurm/slurm_parser.h

check_PROGRAMS  = address.test
check_PROGRAMS += clients.test
check_PROGRAMS += line_file.test
check_PROGRAMS += pdu_handler.test
check_PROGRAMS += rsync.test
check_PROGRAMS += roa_table.test
#check_PROGRAMS += tal.test
check_PROGRAMS += vcard.test
check_PROGRAMS += vrps.test
#check_PROGRAMS += rtr/pdu.test
#check_PROGRAMS += rtr/primitive_reader.test
TESTS = ${check_PROGRAMS}

address_test_SOURCES  = ${BASIC_MODULES}
address_test_SOURCES += ../src/address.h
address_test_SOURCES += address_test.c
address_test_LDADD = ${MY_LDADD}

clients_test_SOURCES  = ${BASIC_MODULES}
clients_test_SOURCES += ../src/clients.c
clients_test_SOURCES += ../src/common.c
clients_test_SOURCES += client_test.c
clients_test_LDADD = ${MY_LDADD}

line_file_test_SOURCES  = ${BASIC_MODULES}
line_file_test_SOURCES += ../src/file.c ../src/file.h
line_file_test_SOURCES += ../src/line_file.c ../src/line_file.h
line_file_test_SOURCES += line_file_test.c
line_file_test_LDADD = ${MY_LDADD}

pdu_handler_test_SOURCES  = ${BASIC_MODULES}
pdu_handler_test_SOURCES += ${SLURM_SOURCES}
pdu_handler_test_SOURCES += ../src/common.c
pdu_handler_test_SOURCES += ../src/rtr/pdu_handler.c
pdu_handler_test_SOURCES += ../src/rtr/err_pdu.c
pdu_handler_test_SOURCES += ../src/rtr/db/delta.c
pdu_handler_test_SOURCES += ../src/rtr/db/roa_table.c
pdu_handler_test_SOURCES += ../src/rtr/db/vrps.c
pdu_handler_test_SOURCES += rtr/db/impersonator.c
pdu_handler_test_SOURCES += rtr/pdu_handler_test.c
pdu_handler_test_LDADD = ${MY_LDADD} ${JANSSON_LIBS}

roa_table_test_SOURCES  = ${BASIC_MODULES}
roa_table_test_SOURCES += ../src/address.c
roa_table_test_SOURCES += ../src/rtr/db/delta.c
roa_table_test_SOURCES += ../src/rtr/db/roa_table.c
roa_table_test_SOURCES += rtr/db/roa_table_test.c
roa_table_test_LDADD = ${MY_LDADD}

rsync_test_SOURCES  = ${BASIC_MODULES}
rsync_test_SOURCES += ../src/str.c ../src/str.h
rsync_test_SOURCES += ../src/uri.c ../src/uri.h
rsync_test_SOURCES += rsync_test.c
rsync_test_LDADD = ${MY_LDADD}

#tal_test_SOURCES  = ${BASIC_MODULES}
#tal_test_SOURCES += ../src/file.c ../src/file.h
#tal_test_SOURCES += ../src/crypto/base64.c ../src/crypto/base64.h
#tal_test_SOURCES += ../src/random.c ../src/random.h
#tal_test_SOURCES += ../src/str.c ../src/str.h
#tal_test_SOURCES += ../src/uri.c ../src/uri.h
#tal_test_SOURCES += ../src/line_file.c ../src/line_file.h
#tal_test_SOURCES += tal_test.c
#tal_test_LDADD = ${MY_LDADD}

vcard_test_SOURCES  = ${BASIC_MODULES}
vcard_test_SOURCES += vcard_test.c
vcard_test_LDADD = ${MY_LDADD}

vrps_test_SOURCES  = ${BASIC_MODULES}
vrps_test_SOURCES += ${SLURM_SOURCES}
vrps_test_SOURCES += ../src/common.c
vrps_test_SOURCES += ../src/rtr/db/delta.c
vrps_test_SOURCES += ../src/rtr/db/roa_table.c
vrps_test_SOURCES += ../src/rtr/db/vrps.c
vrps_test_SOURCES += rtr/db/impersonator.c
vrps_test_SOURCES += rtr/db/vrps_test.c
vrps_test_LDADD = ${MY_LDADD} ${JANSSON_LIBS}

#rtr_pdu_test_SOURCES  = ${BASIC_MODULES}
#rtr_pdu_test_SOURCES += rtr/pdu_test.c
#rtr_pdu_test_SOURCES += rtr/stream.c
#rtr_pdu_test_SOURCES += ../src/rtr/primitive_reader.c
#rtr_pdu_test_SOURCES += ../src/rtr/pdu_handler.c
#rtr_pdu_test_LDADD = ${MY_LDADD}

#rtr_primitive_reader_test_SOURCES  = ${BASIC_MODULES}
#rtr_primitive_reader_test_SOURCES += rtr/primitive_reader_test.c
#rtr_primitive_reader_test_SOURCES += rtr/stream.c
#rtr_primitive_reader_test_LDADD = ${MY_LDADD}
