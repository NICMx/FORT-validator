#include <check.h>

#include "alloc.c"
#include "mock.c"
#include "rsync/rsync.c"

static char const * const PKT = "abcdefghijklmnopqrstuvwxyz";
static const size_t PKTLEN = sizeof(PKT) - 1;

MOCK(config_get_rsync_transfer_timeout, long, 4, void)
__MOCK_ABORT(config_get_rsync_program, char *, NULL, void)
__MOCK_ABORT(config_get_rsync_args, struct string_array const *, NULL, void)
__MOCK_ABORT(config_get_rsync_retry_count, unsigned int, 0, void)
__MOCK_ABORT(config_get_rsync_retry_interval, unsigned int, 0, void)

static void
disable_sigpipe(void)
{
	struct sigaction action = { .sa_handler = SIG_IGN };
	if (sigaction(SIGPIPE, &action, NULL) == -1)
		pr_crit("Cannot disable SIGPIPE: %s", strerror(errno));
}

static void *
rsync_fast(void *arg)
{
	int writefd = *((int *)arg);
	free(arg);

	ck_assert_int_eq(PKTLEN, write(writefd, PKT, PKTLEN));
	ck_assert_int_eq(PKTLEN, write(writefd, PKT, PKTLEN));
	ck_assert_int_eq(PKTLEN, write(writefd, PKT, PKTLEN));
	ck_assert_int_eq(PKTLEN, write(writefd, PKT, PKTLEN));

	close(writefd);
	return NULL;
}

static void *
rsync_stalled(void *arg)
{
	int writefd = *((int *)arg);
	free(arg);

	ck_assert_int_eq(PKTLEN, write(writefd, PKT, PKTLEN));

	sleep(5); /* The timeout is 4 seconds */

	ck_assert_int_ne(PKTLEN, write(writefd, PKT, PKTLEN));

	close(writefd);
	return NULL;
}

static void *
rsync_drip_feed(void *arg)
{
	int writefd = *((int *)arg);
	free(arg);

	ck_assert_int_eq(PKTLEN, write(writefd, PKT, PKTLEN));
	sleep(1);
	ck_assert_int_eq(PKTLEN, write(writefd, PKT, PKTLEN));
	sleep(1);
	ck_assert_int_eq(PKTLEN, write(writefd, PKT, PKTLEN));
	sleep(1);
	ck_assert_int_eq(PKTLEN, write(writefd, PKT, PKTLEN));
	sleep(2);
	ck_assert_int_ne(PKTLEN, write(writefd, PKT, PKTLEN));

	close(writefd);
	return NULL;
}

static void
prepare_test(int fds[2], pthread_t *thread, void *(*rsync_simulator)(void *))
{
	int *arg;

	ck_assert_int_eq(0, pipe(fds));

	arg = pmalloc(sizeof(fds[1]));
	*arg = fds[1];
	ck_assert_int_eq(0, pthread_create(thread, NULL, rsync_simulator, arg));
}

static void
finish_test(pthread_t thread)
{
	pthread_join(thread, NULL);
}

START_TEST(read_pipe_test) /* Tests the read_pipe() function */
{
	int fds[2];
	pthread_t rsync_writer;

	printf("This test needs to exhaust some timeouts. Please be patient.\n");

	printf("Normal transfer\n");
	prepare_test(fds, &rsync_writer, rsync_fast);
	ck_assert_int_eq(0, exhaust_read_fd(fds[0], 0));
	finish_test(rsync_writer);

	printf("Stalled transfer\n");
	prepare_test(fds, &rsync_writer, rsync_stalled);
	ck_assert_int_eq(2, exhaust_read_fd(fds[0], 0));
	finish_test(rsync_writer);

	printf("Drip-feed\n");
	prepare_test(fds, &rsync_writer, rsync_drip_feed);
	ck_assert_int_eq(2, exhaust_read_fd(fds[0], 0));
	finish_test(rsync_writer);
}
END_TEST

static Suite *xml_load_suite(void)
{
	Suite *suite;
	TCase *pipes;

	pipes = tcase_create("pipes");
	tcase_add_test(pipes, read_pipe_test);
	tcase_set_timeout(pipes, 15);

	suite = suite_create("rsync");
	suite_add_tcase(suite, pipes);

	return suite;
}

int main(void)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	disable_sigpipe();

	suite = xml_load_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
