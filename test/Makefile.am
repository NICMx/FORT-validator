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
AM_CFLAGS =  -pedantic -Wall
#AM_CFLAGS += -Wno-unused
AM_CFLAGS += -std=c99 -D_DEFAULT_SOURCE=1 -D_XOPEN_SOURCE=700 -D_BSD_SOURCE=1
AM_CFLAGS += -I../src -DUNIT_TESTING ${CHECK_CFLAGS} ${XML2_CFLAGS} ${JANSSON_CFLAGS}
# Reminder: As opposed to AM_CFLAGS, "AM_LDADD" is not idiomatic automake, and
# autotools will even reprehend us if we declare it. Therefore, I came up with
# "my" own "ldadd". Unlike AM_CFLAGS, it needs to be manually added to every
# target.
MY_LDADD = ${CHECK_LIBS} ${JANSSON_LIBS}

check_PROGRAMS  = cachent.test
check_PROGRAMS += cache.test
TESTS = ${check_PROGRAMS}

cache_test_SOURCES = cache/local_cache_test.c
cache_test_LDADD = ${MY_LDADD} ${JANSSON_LIBS}

cachent_test_SOURCES = cache/cachent_test.c
cachent_test_LDADD = ${MY_LDADD} ${JANSSON_LIBS}

EXTRA_DIST  = mock.c mock.h
EXTRA_DIST += resources/lorem-ipsum.txt
EXTRA_DIST += rtr/db/rtr_db_mock.c
EXTRA_DIST += tal/lacnic.tal
EXTRA_DIST += xml/notification.xml

endif
