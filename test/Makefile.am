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
# The extra info provided by this flag allows the linker to strip unused
# symbols, which reduces required superfluous #includes and mocks.
# It's supported by gcc and clang, not sure about others.
AM_CFLAGS += -flto
AM_CFLAGS += -std=c99 -D_XOPEN_SOURCE=700
# Most (if not all) tests need common.c, which needs timegm()
AM_CFLAGS += -D_DEFAULT_SOURCE=1 -D_DARWIN_C_SOURCE=1
AM_CFLAGS += -I../src -DUNIT_TESTING
AM_CFLAGS += ${CHECK_CFLAGS} ${XML2_CFLAGS} ${JANSSON_CFLAGS}
# AM_LDFLAGS isn't working on Linux, and "AM_LDADD" is not idiomatic
# automake. (autotools will reprehend us if we declare it.)


check_PROGRAMS =		address.test
address_test_SOURCES =		types/address_test.c
address_test_LDADD =		${CHECK_LIBS}

check_PROGRAMS +=		asn1_int.test
asn1_int_test_SOURCES =		asn1/asn1c/INTEGER_t_test.c
asn1_int_test_LDADD =		${CHECK_LIBS}

check_PROGRAMS +=		asn1_stream.test
asn1_stream_test_SOURCES =	asn1/asn1c/asn1stream_test.c
asn1_stream_test_LDADD =	${CHECK_LIBS}

check_PROGRAMS +=		base64.test
base64_test_SOURCES =		base64_test.c
base64_test_LDADD =		${CHECK_LIBS}

check_PROGRAMS +=		cache.test
cache_test_SOURCES =		cache_test.c
cache_test_LDADD =		${CHECK_LIBS}
cache_test_LDADD +=		${CURL_LIBS}
cache_test_LDADD +=		${XML2_LIBS}
cache_test_LDADD +=		${JANSSON_LIBS}

check_PROGRAMS +=		common.test
common_test_SOURCES =		common_test.c
common_test_LDADD =		${CHECK_LIBS}

check_PROGRAMS +=		db_table.test
db_table_test_SOURCES =		rtr/db/db_table_test.c
db_table_test_LDADD =		${CHECK_LIBS}

check_PROGRAMS +=		deltas_array.test
deltas_array_test_SOURCES =	rtr/db/deltas_array_test.c
deltas_array_test_LDADD =	${CHECK_LIBS}

check_PROGRAMS +=		hash.test
hash_test_SOURCES =		hash_test.c
hash_test_LDADD =		${CHECK_LIBS}

check_PROGRAMS +=		mft.test
mft_test_SOURCES =		object/manifest_test.c
mft_test_LDADD =		${CHECK_LIBS}

check_PROGRAMS +=		pdu_handler.test
pdu_handler_test_SOURCES =	rtr/pdu_handler_test.c
pdu_handler_test_LDADD =	${CHECK_LIBS}

check_PROGRAMS +=		pdu_stream.test
pdu_stream_test_SOURCES =	rtr/pdu_stream_test.c
pdu_stream_test_LDADD =		${CHECK_LIBS}

check_PROGRAMS +=		rrdp.test
rrdp_test_SOURCES =		rrdp_test.c
rrdp_test_LDADD =		${CHECK_LIBS}
rrdp_test_LDADD +=		${CURL_LIBS}
rrdp_test_LDADD +=		${XML2_LIBS}
rrdp_test_LDADD +=		${JANSSON_LIBS}

check_PROGRAMS +=		rrdp_update.test
rrdp_update_test_SOURCES =	rrdp_update_test.c
rrdp_update_test_LDADD =	${CHECK_LIBS}
rrdp_update_test_LDADD +=	${CURL_LIBS}
rrdp_update_test_LDADD +=	${XML2_LIBS}
rrdp_update_test_LDADD +=	${JANSSON_LIBS}

check_PROGRAMS +=		rsync.test
rsync_test_SOURCES =		rsync_test.c
rsync_test_LDADD =		${CHECK_LIBS}
rsync_test_LDADD +=		${CURL_LIBS}

check_PROGRAMS +=		serial.test
serial_test_SOURCES =		types/serial_test.c
serial_test_LDADD =		${CHECK_LIBS}

#check_PROGRAMS +=		stream.test
#stream_test_SOURCES =		stream_test.c
#stream_test_LDADD =		${CHECK_LIBS}

check_PROGRAMS +=		tal.test
tal_test_SOURCES =		object/tal_test.c
tal_test_LDADD =		${CHECK_LIBS}
tal_test_LDADD +=		${CURL_LIBS}

check_PROGRAMS +=		task.test
task_test_SOURCES =		task_test.c
task_test_LDADD =		${CHECK_LIBS}

check_PROGRAMS +=		thread_pool.test
thread_pool_test_SOURCES =	thread_pool_test.c
thread_pool_test_LDADD =	${CHECK_LIBS}

check_PROGRAMS +=		uri.test
uri_test_SOURCES =		types/uri_test.c
uri_test_LDADD =		${CHECK_LIBS}
uri_test_LDADD +=		${CURL_LIBS}

check_PROGRAMS +=		uthash.test
uthash_test_SOURCES =		types/uthash_test.c
uthash_test_LDADD =		${CHECK_LIBS}

check_PROGRAMS +=		vcard.test
vcard_test_SOURCES =		vcard_test.c
vcard_test_LDADD =		${CHECK_LIBS}

check_PROGRAMS +=		vrps.test
vrps_test_SOURCES =		rtr/db/vrps_test.c
vrps_test_LDADD =		${CHECK_LIBS}

check_PROGRAMS +=		xml.test
xml_test_SOURCES =		xml_test.c
xml_test_LDADD =		${CHECK_LIBS}
xml_test_LDADD +=		${XML2_LIBS}

TESTS = ${check_PROGRAMS}


EXTRA_DIST  = mock.c mock.h
EXTRA_DIST += resources/lorem-ipsum.txt
EXTRA_DIST += rtr/db/rtr_db_mock.c
EXTRA_DIST += tal/lacnic.tal
EXTRA_DIST += xml/notification.xml

clean-local:
	rm -rf tmp/ # test sandboxes

endif
