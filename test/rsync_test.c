#include <check.h>

#include "alloc.c"
#include "common.c"
#include "mock.c"
#include "rsync.c"

static char const STR64[] = "abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"0123456789 \n";
static const size_t STR64LEN = sizeof(STR64) - 1;
static char content[1024];

/* Mocks */

MOCK(config_get_rsync_program, char const *, "rsync", void)
MOCK_UINT(config_get_rsync_retry_count, 0, void)
MOCK_UINT(config_get_rsync_retry_interval, 10, void)
MOCK(config_get_rsync_transfer_timeout, long, 4, void)

void
log_flush(void)
{
	fflush(stdout);
	fflush(stderr);
}

/* Tests */

static void
disable_sigpipe(void)
{
	struct sigaction action = { .sa_handler = SIG_IGN };
	if (sigaction(SIGPIPE, &action, NULL) == -1)
		pr_crit("Cannot disable SIGPIPE: %s", strerror(errno));
}

static void
init_content(void)
{
	size_t i;

	if (sizeof(content) % STR64LEN != 0)
		pr_crit("content's length isn't divisible by str64's length");
	for (i = 0; i < (sizeof(content) / STR64LEN); i++)
		memcpy(content + 64 * i, STR64, STR64LEN);
}

static void
init_tmp(void)
{
	int res = mkdir("tmp/", 0700);
	if (res && errno != EEXIST)
		pr_crit("Could not create tmp/: %s", strerror(errno));
}

static void *
rsync_fast(void *arg)
{
	int fds[2][2];
	memcpy(fds, arg, sizeof(fds));

	ck_assert_int_eq(STR64LEN, write(STDERR_WRITE(fds), STR64, STR64LEN));
	ck_assert_int_eq(STR64LEN, write(STDOUT_WRITE(fds), STR64, STR64LEN));
	ck_assert_int_eq(STR64LEN, write(STDERR_WRITE(fds), STR64, STR64LEN));
	ck_assert_int_eq(STR64LEN, write(STDOUT_WRITE(fds), STR64, STR64LEN));

	close(STDERR_WRITE(fds));
	close(STDOUT_WRITE(fds));
	return NULL;
}

static void *
rsync_stalled(void *arg)
{
	int fds[2][2];
	memcpy(fds, arg, sizeof(fds));

	ck_assert_int_eq(STR64LEN, write(STDOUT_WRITE(fds), STR64, STR64LEN));

	sleep(5); /* The timeout is 4 seconds */

	ck_assert_int_ne(STR64LEN, write(STDOUT_WRITE(fds), STR64, STR64LEN));

	close(STDERR_WRITE(fds));
	close(STDOUT_WRITE(fds));
	return NULL;
}

static void *
rsync_drip_feed(void *arg)
{
	int fds[2][2];
	memcpy(fds, arg, sizeof(fds));

	ck_assert_int_eq(STR64LEN, write(STDOUT_WRITE(fds), STR64, STR64LEN));
	sleep(1);
	ck_assert_int_eq(STR64LEN, write(STDOUT_WRITE(fds), STR64, STR64LEN));
	ck_assert_int_eq(STR64LEN, write(STDERR_WRITE(fds), STR64, STR64LEN));
	sleep(1);
	ck_assert_int_eq(STR64LEN, write(STDOUT_WRITE(fds), STR64, STR64LEN));
	sleep(1);
	ck_assert_int_eq(STR64LEN, write(STDERR_WRITE(fds), STR64, STR64LEN));
	sleep(2);
	ck_assert_int_ne(STR64LEN, write(STDOUT_WRITE(fds), STR64, STR64LEN));

	close(STDERR_WRITE(fds));
	close(STDOUT_WRITE(fds));
	return NULL;
}

static void
prepare_exhaust(int fds[2][2], pthread_t *thread, void *(*rsync_simulator)(void *))
{
	ck_assert_int_eq(0, pipe(fds[0]));
	ck_assert_int_eq(0, pipe(fds[1]));
	ck_assert_int_eq(0, pthread_create(thread, NULL, rsync_simulator, fds));
}

static void
finish_exhaust(pthread_t thread)
{
	pthread_join(thread, NULL);
}

START_TEST(exhaust_read_fds_test_normal)
{
	int fds[2][2];
	pthread_t rsync_writer;

	printf("Normal transfer\n");
	prepare_exhaust(fds, &rsync_writer, rsync_fast);
	ck_assert_int_eq(0, exhaust_read_fds(STDERR_READ(fds), STDOUT_READ(fds)));
	finish_exhaust(rsync_writer);
}
END_TEST

START_TEST(exhaust_read_fds_test_stalled)
{
	int fds[2][2];
	pthread_t rsync_writer;

	printf("Stalled transfer\n");
	prepare_exhaust(fds, &rsync_writer, rsync_stalled);
	ck_assert_int_eq(2, exhaust_read_fds(STDERR_READ(fds), STDOUT_READ(fds)));
	finish_exhaust(rsync_writer);
}
END_TEST

START_TEST(exhaust_read_fds_test_drip)
{
	int fds[2][2];
	pthread_t rsync_writer;

	printf("Drip-feed\n");
	prepare_exhaust(fds, &rsync_writer, rsync_drip_feed);
	ck_assert_int_eq(2, exhaust_read_fds(STDERR_READ(fds), STDOUT_READ(fds)));
	finish_exhaust(rsync_writer);
}
END_TEST

static void
create_file(char const *name, unsigned int kbs)
{
	FILE *file;
	unsigned int k;

	file = fopen(name, "wb");
	ck_assert_ptr_ne(NULL, file);
	for (k = 0; k < kbs; k++)
		ck_assert_int_eq(sizeof(content), fwrite(content, 1, sizeof(content), file));
	ck_assert_int_eq(0, fclose(file));
}

static void
ensure_file_deleted(char const *name)
{
	int ret;
	int error;

	errno = 0;
	ret = unlink(name);
	error = errno;

	ck_assert(ret == 0 || error == ENOENT);
}

START_TEST(full_rsync_timeout_test_1kb)
{
	printf("1kb\n");
	create_file("tmp/1kb", 1);
	ensure_file_deleted("tmp/1kb-copy");
	// XXX this is creating directories because of rsync_download's mkdir_p.
	// Is this a symptom of a problem?
	ck_assert_int_eq(0, rsync_download("tmp/1kb", "tmp/1kb-copy"));
}
END_TEST

START_TEST(full_rsync_timeout_test_3kb)
{
	printf("3kb\n");
	create_file("tmp/3kb", 3);
	ensure_file_deleted("tmp/3kb-copy");
	ck_assert_int_eq(0, rsync_download("tmp/3kb", "tmp/3kb-copy"));
}
END_TEST

START_TEST(full_rsync_timeout_test_5kb)
{
	printf("5kb\n");
	create_file("tmp/5kb", 5);
	ensure_file_deleted("tmp/5kb-copy");
	/* Max speed is 1kbps, timeout is 4 seconds */
	ck_assert_int_eq(EIO, rsync_download("tmp/5kb", "tmp/5kb-copy"));
}
END_TEST

static Suite *xml_load_suite(void)
{
	Suite *suite;
	TCase *pipes;

	pipes = tcase_create("pipes");
	tcase_add_test(pipes, exhaust_read_fds_test_normal);
	tcase_add_test(pipes, exhaust_read_fds_test_stalled);
	tcase_add_test(pipes, exhaust_read_fds_test_drip);
	tcase_add_test(pipes, full_rsync_timeout_test_1kb);
	tcase_add_test(pipes, full_rsync_timeout_test_3kb);
	tcase_add_test(pipes, full_rsync_timeout_test_5kb);
	tcase_set_timeout(pipes, 6);

	suite = suite_create("rsync");
	suite_add_tcase(suite, pipes);

	return suite;
}

int main(void)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	printf("This test needs to exhaust some timeouts. Please be patient.\n");
	disable_sigpipe();
	init_content();
	init_tmp();

	suite = xml_load_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
