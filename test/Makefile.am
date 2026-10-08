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
AM_CFLAGS =  -Wall -Wpedantic
# Strip unused symbols (Reduces the need for superfluous #includes & mocks)
AM_CFLAGS += -Os -flto
AM_CFLAGS += -std=c99 -D_XOPEN_SOURCE=700
AM_CFLAGS += -D_DEFAULT_SOURCE=1 -D_DARWIN_C_SOURCE=1
AM_CFLAGS += -I../src -DUNIT_TESTING
AM_CFLAGS += ${CHECK_CFLAGS} ${JANSSON_CFLAGS}
# AM_LDFLAGS isn't working on Linux, and "AM_LDADD" is not idiomatic
# automake. (autotools will reprehend us if we declare it.)


check_PROGRAMS =		address.test
address_test_SOURCES =		validator/asn1/decode_test.c
address_test_LDADD =		${CHECK_LIBS}

check_PROGRAMS +=		asn1_int.test
asn1_int_test_SOURCES =		validator/asn1/asn1c/INTEGER_t_test.c
asn1_int_test_LDADD =		${CHECK_LIBS}

check_PROGRAMS +=		asn1_stream.test
asn1_stream_test_SOURCES =	validator/asn1/asn1c/asn1stream_test.c
asn1_stream_test_LDADD =	${CHECK_LIBS} ${JANSSON_LIBS}

check_PROGRAMS +=		base64.test
base64_test_SOURCES =		validator/base64_test.c
base64_test_LDADD =		${CHECK_LIBS}

check_PROGRAMS +=		cache.test
cache_test_SOURCES =		validator/cache_test.c
cache_test_LDADD =		${CHECK_LIBS} ${JANSSON_LIBS}

check_PROGRAMS +=		common.test
common_test_SOURCES =		common/common_test.c
common_test_LDADD =		${CHECK_LIBS}

check_PROGRAMS +=		db_table.test
db_table_test_SOURCES =		validator/db/db_table_test.c
db_table_test_LDADD =		${CHECK_LIBS}

check_PROGRAMS +=		hash.test
hash_test_SOURCES =		validator/hash_test.c
hash_test_LDADD =		${CHECK_LIBS}

check_PROGRAMS +=		mft.test
mft_test_SOURCES =		validator/object/manifest_test.c
mft_test_LDADD =		${CHECK_LIBS}

check_PROGRAMS +=		path.test
path_test_SOURCES =		common/types/path_test.c
path_test_LDADD =		${CHECK_LIBS}

check_PROGRAMS +=		pdu_handler.test
pdu_handler_test_SOURCES =	rtr/pdu_handler_test.c
pdu_handler_test_LDADD =	${CHECK_LIBS} ${JANSSON_LIBS}

check_PROGRAMS +=		pdu_stream.test
pdu_stream_test_SOURCES =	rtr/pdu_stream_test.c
pdu_stream_test_LDADD =		${CHECK_LIBS} ${JANSSON_LIBS}

check_PROGRAMS +=		rrdp.test
rrdp_test_SOURCES =		validator/rrdp_test.c
rrdp_test_LDADD =		${CHECK_LIBS} ${JANSSON_LIBS}

check_PROGRAMS +=		rrdp_xml.test
rrdp_xml_test_SOURCES =		validator/rrdp_xml_test.c
rrdp_xml_test_LDADD =		${CHECK_LIBS} ${JANSSON_LIBS}

#check_PROGRAMS +=		rsync.test
#rsync_test_SOURCES =		validator/rsync_test.c
#rsync_test_LDADD =		${CHECK_LIBS}

check_PROGRAMS +=		serial.test
serial_test_SOURCES =		common/types/serial_test.c
serial_test_LDADD =		${CHECK_LIBS}

#check_PROGRAMS +=		stream.test
#stream_test_SOURCES =		validator/stream_test.c
#stream_test_LDADD =		${CHECK_LIBS}

check_PROGRAMS +=		tal.test
tal_test_SOURCES =		validator/object/tal_test.c
tal_test_LDADD =		${CHECK_LIBS}

check_PROGRAMS +=		task.test
task_test_SOURCES =		validator/task_test.c
task_test_LDADD =		${CHECK_LIBS}

check_PROGRAMS +=		uri.test
uri_test_SOURCES =		common/types/uri_test.c
uri_test_LDADD =		${CHECK_LIBS}

check_PROGRAMS +=		uthash.test
uthash_test_SOURCES =		common/types/uthash_test.c
uthash_test_LDADD =		${CHECK_LIBS}

check_PROGRAMS +=		vcard.test
vcard_test_SOURCES =		validator/object/vcard_test.c
vcard_test_LDADD =		${CHECK_LIBS}


TESTS = ${check_PROGRAMS}


EXTRA_DIST  = mock.c mock.h

clean-local:
	rm -rf tmp/ # test sandboxes

endif
