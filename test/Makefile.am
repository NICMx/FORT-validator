if USE_TESTS

# Reminder: `make check`

# If you want to only run one test, do `make check TESTS=<test>`.
# Example: `make check TESTS=address`

# Once compiled, you can also just run the test directly: `./address.test`
# You can easily see standard output and error this way.

# Reminder: Automake will automatically add this to any targets where
# <mumble>_CFLAGS is not defined.
# Otherwise it must be included manually:
# 	mumble_mumble_CFLAGS = ${AM_CFLAGS} flag1 flag2 flag3 ...
AM_CFLAGS = -pedantic -Wall -std=gnu11 -I../src -DUNIT_TESTING ${CHECK_CFLAGS} ${XML2_CFLAGS}
# Reminder: As opposed to AM_CFLAGS, "AM_LDADD" is not idiomatic automake, and
# autotools will even reprehend us if we declare it. Therefore, I came up with
# "my" own "ldadd". Unlike AM_CFLAGS, it needs to be manually added to every
# target.
MY_LDADD = ${CHECK_LIBS}

check_PROGRAMS  = address.test
check_PROGRAMS += deltas_array.test
check_PROGRAMS += db_table.test
check_PROGRAMS += line_file.test
check_PROGRAMS += pdu_handler.test
check_PROGRAMS += rrdp_objects.test
check_PROGRAMS += rsync.test
check_PROGRAMS += serial.test
check_PROGRAMS += tal.test
check_PROGRAMS += thread_pool.test
check_PROGRAMS += uri.test
check_PROGRAMS += vcard.test
check_PROGRAMS += vrps.test
check_PROGRAMS += xml.test
check_PROGRAMS += rtr/pdu.test
check_PROGRAMS += rtr/primitive_reader.test
TESTS = ${check_PROGRAMS}

address_test_SOURCES = types/address_test.c
address_test_LDADD = ${MY_LDADD}

deltas_array_test_SOURCES = rtr/db/deltas_array_test.c
deltas_array_test_LDADD = ${MY_LDADD}

db_table_test_SOURCES = rtr/db/db_table_test.c
db_table_test_LDADD = ${MY_LDADD}

line_file_test_SOURCES = line_file_test.c
line_file_test_LDADD = ${MY_LDADD}

pdu_handler_test_SOURCES = rtr/pdu_handler_test.c
pdu_handler_test_LDADD = ${MY_LDADD} ${JANSSON_LIBS}

rrdp_objects_test_SOURCES = rrdp_objects_test.c
rrdp_objects_test_LDADD = ${MY_LDADD} ${JANSSON_LIBS} ${XML2_LIBS}

rsync_test_SOURCES = rsync_test.c
rsync_test_LDADD = ${MY_LDADD}

serial_test_SOURCES = types/serial_test.c
serial_test_LDADD = ${MY_LDADD}

tal_test_SOURCES = tal_test.c
tal_test_LDADD = ${MY_LDADD}

thread_pool_test_SOURCES = thread_pool_test.c
thread_pool_test_LDADD = ${MY_LDADD}

uri_test_SOURCES = types/uri_test.c
uri_test_LDADD = ${MY_LDADD}

vcard_test_SOURCES = vcard_test.c
vcard_test_LDADD = ${MY_LDADD}

vrps_test_SOURCES = rtr/db/vrps_test.c
vrps_test_LDADD = ${MY_LDADD} ${JANSSON_LIBS}

xml_test_SOURCES = xml_test.c
xml_test_LDADD = ${MY_LDADD} ${XML2_LIBS}

rtr_pdu_test_SOURCES = rtr/pdu_test.c
rtr_pdu_test_LDADD = ${MY_LDADD}

rtr_primitive_reader_test_SOURCES = rtr/primitive_reader_test.c
rtr_primitive_reader_test_LDADD = ${MY_LDADD}

EXTRA_DIST  = impersonator.c
EXTRA_DIST += line_file/core.txt
EXTRA_DIST += line_file/empty.txt
EXTRA_DIST += line_file/error.txt
EXTRA_DIST += rtr/db/rtr_db_impersonator.c
EXTRA_DIST += tal/lacnic.tal
EXTRA_DIST += xml/notification.xml

endif
