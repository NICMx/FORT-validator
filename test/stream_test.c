#include <check.h>
#include <pthread.h>

#include "alloc.c"
#include "mock.c"
#include "stream.c"

#define DO_WRITE(fd, str) ck_assert_int_eq(0, stream_wr_str(fd, str))
#define CK_READ(stm, str) do {						\
		ck_assert_int_eq(0, rstream_read_str(&stm, &rcvd));	\
		ck_assert_str_eq(str, rcvd);				\
		free(rcvd);						\
	} while (0)
#define CK_READ_END(stm) do {						\
		ck_assert_int_eq(0, rstream_read_str(&stm, &rcvd));	\
		ck_assert_ptr_eq(NULL, rcvd);				\
	} while (0);

static char large[1025];

START_TEST(test_string_simple)
{
	int fds[2];
	struct read_stream stream;
	char *rcvd;

	ck_assert_int_eq(0, pipe(fds));
	rstream_init(&stream, fds[0], 128);

	DO_WRITE(fds[1], "Lorem ipsum dolor sit amet");
	CK_READ(stream, "Lorem ipsum dolor sit amet");
	close(fds[1]);
	CK_READ_END(stream);

	rstream_close(&stream, true);
}
END_TEST

START_TEST(test_string_simple_alt)
{
	int fds[2];
	struct read_stream stream;
	char *rcvd;

	ck_assert_int_eq(0, pipe(fds));
	rstream_init(&stream, fds[0], 128);

	DO_WRITE(fds[1], "Lorem ipsum dolor sit amet");
	close(fds[1]);
	CK_READ(stream, "Lorem ipsum dolor sit amet");
	CK_READ_END(stream);

	rstream_close(&stream, true);
}
END_TEST

START_TEST(test_string_multiple)
{
	int fds[2];
	struct read_stream stream;
	char *rcvd;

	ck_assert_int_eq(0, pipe(fds));
	rstream_init(&stream, fds[0], 128);

	/* Write 3 separate strings, close immediately */
	DO_WRITE(fds[1], "Lorem ipsum dolor sit amet");
	DO_WRITE(fds[1], "consectetur adipiscing elit");
	DO_WRITE(fds[1], "Curabitur scelerisque tortor est");
	close(fds[1]);

	/* Read each string separately, then check read end */
	CK_READ(stream, "Lorem ipsum dolor sit amet");
	CK_READ(stream, "consectetur adipiscing elit");
	CK_READ(stream, "Curabitur scelerisque tortor est");
	CK_READ_END(stream);

	rstream_close(&stream, true);
}
END_TEST

START_TEST(test_string_capacity_growth)
{
	int fds[2];
	struct read_stream stream;
	char *rcvd;

	ck_assert_int_eq(0, pipe(fds));
	rstream_init(&stream, fds[0], 16);

	DO_WRITE(fds[1], "Lorem ipsum dolor sit amet, consectetur adipiscing elit.");
	DO_WRITE(fds[1], "Curabitur scelerisque tortor est, ut lacinia eros rutrum id. Duis sed metus id nisl suscipit facilisis.");
	DO_WRITE(fds[1], "Mauris at varius libero.");
	close(fds[1]);
	CK_READ(stream, "Lorem ipsum dolor sit amet, consectetur adipiscing elit.");
	ck_assert_uint_eq(64, stream.capacity);
	CK_READ(stream, "Curabitur scelerisque tortor est, ut lacinia eros rutrum id. Duis sed metus id nisl suscipit facilisis.");
	ck_assert_uint_eq(128, stream.capacity);
	CK_READ(stream, "Mauris at varius libero.");
	ck_assert_uint_eq(128, stream.capacity);
	CK_READ_END(stream);

	rstream_close(&stream, true);
}
END_TEST

START_TEST(test_string_max_size)
{
	int fds[2];
	struct read_stream stream;
	char *rcvd;

	/* strlen(src) = 1023: Success */

	memset(large, 'a', 1023);
	large[1023] = 0;

	ck_assert_int_eq(0, pipe(fds));
	rstream_init(&stream, fds[0], 256);

	DO_WRITE(fds[1], large);
	close(fds[1]);
	CK_READ(stream, large);
	CK_READ_END(stream);

	rstream_close(&stream, true);

	/* strlen(src) = 1024: Fail */

	large[1023] = 'b';
	large[1024] = 0;

	ck_assert_int_eq(0, pipe(fds));
	rstream_init(&stream, fds[0], 256);

	ck_assert_int_eq(EBADLEN, stream_wr_str(fds[1], large));
	close(fds[1]);
	CK_READ_END(stream);

	rstream_close(&stream, true);
}
END_TEST

static void *
consume_fragments(void *arg)
{
	struct read_stream stream;
	char *rcvd;

	rstream_init(&stream, *((int *)arg), 128);

	CK_READ(stream, "1234567890abcdefghijABCDEFGHI");
	CK_READ_END(stream);
	rstream_close(&stream, true);

	return NULL;
}

START_TEST(test_string_fragmented)
{
	pthread_t reader;
	int fds[2];

	ck_assert_int_eq(0, pipe(fds));
	ck_assert_int_eq(0, pthread_create(&reader, NULL, consume_fragments, &fds[0]));

	ck_assert_int_eq(0, write_size_t(fds[1], 30));
	ck_assert_int_eq(0, full_write(fds[1], (unsigned char *)"1234567890", 10));
	sleep(1);
	ck_assert_int_eq(0, full_write(fds[1], (unsigned char *)"abcdefghij", 10));
	sleep(1);
	ck_assert_int_eq(0, full_write(fds[1], (unsigned char *)"ABCDEFGHI", 10));
	close(fds[1]);

	ck_assert_int_eq(0, pthread_join(reader, NULL));
}
END_TEST

static void *
consume_many(void *arg)
{
	struct read_stream stream;
	unsigned int i;
	char *rcvd;

	rstream_init(&stream, *((int *)arg), 256);

	for (i = 0; i < 16384; i++)
		CK_READ(stream, large);
	CK_READ_END(stream);
	rstream_close(&stream, true);

	return NULL;
}

START_TEST(test_string_many)
{
	int fds[2];
	pthread_t reader;
	unsigned int i;

	memset(large, 'a', 1023);
	large[1023] = 0;

	ck_assert_int_eq(0, pipe(fds));
	ck_assert_int_eq(0, pthread_create(&reader, NULL, consume_many, &fds[0]));

	for (i = 0; i < 16384; i++)
		DO_WRITE(fds[1], large);
	close(fds[1]);

	ck_assert_int_eq(0, pthread_join(reader, NULL));
}
END_TEST

static Suite *
create_suite(void)
{
	Suite *suite;
	TCase *string;

	string = tcase_create("string");
	tcase_add_test(string, test_string_simple);
	tcase_add_test(string, test_string_simple_alt);
	tcase_add_test(string, test_string_multiple);
	tcase_add_test(string, test_string_capacity_growth);
	tcase_add_test(string, test_string_max_size);
	tcase_add_test(string, test_string_fragmented);
	tcase_add_test(string, test_string_many);

	suite = suite_create("stream");
	suite_add_tcase(suite, string);

	return suite;
}

int
main(void)
{
	SRunner *runner;
	int failures;

	runner = srunner_create(create_suite());
	srunner_run_all(runner, CK_NORMAL);
	failures = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (failures == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
