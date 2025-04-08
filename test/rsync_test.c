#include <check.h>

#include "alloc.c"
#include "common.c"
#include "mock.c"
#include "rsync.c"
#include "stream.c"


#include "asn1/asn1c/ber_decoder.c"
#include "asn1/asn1c/ber_tlv_length.c"
#include "asn1/asn1c/ber_tlv_tag.c"
#include "asn1/asn1c/constr_SEQUENCE.c"
#include "asn1/asn1c/constr_TYPE.c"
#include "asn1/asn1c/der_encoder.c"
#include "asn1/asn1c/OCTET_STRING.c"
#include "asn1/asn1c/RsyncRequest.c"

static char const STR64[] = "abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"0123456789 \n";
static const size_t STR64LEN = sizeof(STR64) - 1;
static char content[1024];

#define BUFSIZE 128

/* Mocks */

MOCK(config_get_rsync_program, char const *, "rsync", void)
MOCK(config_get_rsync_transfer_timeout, long, 4, void)
MOCK_UINT(config_get_asn1_decode_max_stack, 16 * 1024, void)

MOCK_ABORT_PTR(json_obj_new, json_t, void)
MOCK_ABORT_VOID(json_delete, json_t *json)
MOCK_ABORT_PTR(json_strn_new, json_t, const char *value, size_t len)
MOCK_ABORT_PTR(json_null, json_t, void)

static asn_dec_rval_t trash;
__MOCK_ABORT(OPEN_TYPE_ber_get, asn_dec_rval_t, trash,
    const asn_codec_ctx_t *opt_codec_ctx, const asn_TYPE_descriptor_t *td,
    void *sptr, const asn_TYPE_member_t *elm, const void *ptr, size_t size)
MOCK_ABORT_INT(asn_generic_no_constraint, const asn_TYPE_descriptor_t *td,
                const void *strt, asn_app_constraint_failed_f *cb, void *key)

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
create_dir(char const *path)
{
	if (mkdir(path, 0700) < 0)
		ck_assert_int_eq(EEXIST, errno);
}

static void
create_file(char const *name, unsigned int kbs)
{
	FILE *file;

	file = fopen(name, "wb");
	ck_assert_ptr_ne(NULL, file);
	ck_assert_int_eq(kbs, fwrite(content, sizeof(content), kbs, file));
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

static void
create_rsync_sandbox(void)
{
	create_dir("tmp");
	create_dir("tmp/rsync");
	create_dir("tmp/rsync/src");
	create_dir("tmp/rsync/dst");

	create_file("tmp/rsync/src/a", 1);
	create_file("tmp/rsync/src/b", 1);
	create_file("tmp/rsync/src/c", 1);

	ensure_file_deleted("tmp/rsync/dst/a");
	ensure_file_deleted("tmp/rsync/dst/b");
	ensure_file_deleted("tmp/rsync/dst/c");
}

static void
diff(char const *file1, char const *file2)
{
	int fd1, fd2;
	struct read_stream rs1, rs2;
	int read1, read2;

	fd1 = open(file1, O_RDONLY, 0);
	ck_assert_int_ne(-1, fd1);
	rstream_init(&rs1, fd1, 1024);

	fd2 = open(file2, O_RDONLY, 0);
	ck_assert_int_ne(-1, fd2);
	rstream_init(&rs2, fd2, 1024);

	do {
		read1 = rstream_full_read(&rs1, 1024);
		ck_assert_int_ge(read1, 0);
		read2 = rstream_full_read(&rs2, 1024);
		ck_assert_int_eq(read1, read2);
		ck_assert_int_eq(0, memcmp(rs1.buffer, rs2.buffer, read1));
	} while (read1 == 1024);

	rstream_close(&rs1, true);
	rstream_close(&rs2, true);
}

static void
ck_1st_task(struct rsync_tasks *tasks, struct s2p_socket *sk,
    char const *url, char const *path)
{
	struct rsync_task *task;

	task = LIST_FIRST(tasks);
	ck_assert_ptr_ne(NULL, task);
	ck_assert_str_eq(url, task->url);
	ck_assert_str_eq(path, task->path);
	finish_task(task, sk);
}

/* Test RsyncRequest decode, feeding as few bytes as possible every time. */
START_TEST(test_decode_extremely_fragmented)
{
	struct RsyncRequest src, *dst;
	unsigned char encoded[BUFSIZE];
	asn_enc_rval_t encres;
	asn_dec_rval_t decres;
	unsigned int start, end, max;

	ck_assert_int_eq(0, RsyncRequest_init(&src,
	    "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
	    "AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"));
	encres = der_encode_to_buffer(&asn_DEF_RsyncRequest, &src,
	    encoded, sizeof(encoded));
	ck_assert_int_gt(encres.encoded, 0);

	printf("size: %zu\n", encres.encoded);

	dst = NULL;
	max = 0;
	for (start = end = 0; end < encres.encoded - 1; end++) {
		printf("Offset %u: Requesting %u bytes...\n",
		    start, end - start + 1);
		decres = ber_decode(&asn_DEF_RsyncRequest, (void **)&dst,
		    encoded + start, end - start + 1);
		ck_assert_int_eq(RC_WMORE, decres.code);
		start += decres.consumed;

		printf("Consumed %zu bytes.\n", decres.consumed);
		if (decres.consumed > max)
			max = decres.consumed;
	}

	printf("Minimum required buffer size: %u bytes\n", max);

	decres = ber_decode(&asn_DEF_RsyncRequest,
	    (void **)&dst, encoded + start, end - start + 1);
	ck_assert_int_eq(RC_OK, decres.code);
	ck_assert_uint_eq(end - start + 1, decres.consumed);

	ck_assert_int_eq(0, OCTET_STRING_cmp(&src.url, &dst->url));
	ck_assert_int_eq(0, OCTET_STRING_cmp(&src.path, &dst->path));

	ASN_STRUCT_RESET(asn_DEF_RsyncRequest, &src);
	ASN_STRUCT_FREE(asn_DEF_RsyncRequest, dst);
}
END_TEST

static void
encode_request(char const *url, char const *path, unsigned char *buffer)
{
	struct RsyncRequest rr;
	asn_enc_rval_t encres;

	ck_assert_int_eq(0, RsyncRequest_init(&rr, url, path));
	encres = der_encode_to_buffer(&asn_DEF_RsyncRequest, &rr, buffer, BUFSIZE);
	ck_assert_int_gt(encres.encoded, 0);
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RsyncRequest, &rr);
}

/*
 * Tests messy request queuing; in particular, when a single read() yields less
 * than one or multiple of them.
 */
START_TEST(test_read_tasks)
{
	unsigned char bytes[BUFSIZE];
	int fds[2];
	struct s2p_socket sk;
	struct rsync_tasks tasks;
	struct timespec now;

	ck_assert_int_eq(0, nonblock_pipe(fds));
	rstream_init(&sk.rd, fds[0], 256);
	sk.wr = -1;
	sk.rr = NULL;
	LIST_INIT(&tasks);
	ts_now(&now);

	printf("Read yields nothing\n");
	ck_assert_uint_eq(0, read_tasks(&sk, &tasks, &now));

	printf("Read yields less than 1 request\n");
	encode_request("111", "2222", bytes); /* 13 bytes */
	ck_assert_int_eq(0, stream_full_write(fds[1], bytes, 10));
	ck_assert_uint_eq(0, read_tasks(&sk, &tasks, &now));

	ck_assert_int_eq(0, stream_full_write(fds[1], bytes + 10, 3));
	ck_assert_uint_eq(1, read_tasks(&sk, &tasks, &now));

	ck_1st_task(&tasks, &sk, "111", "2222");
	ck_assert(LIST_EMPTY(&tasks));

	printf("Read yields 1 request\n");
	encode_request("3333", "444", bytes); /* 13 bytes */
	ck_assert_int_eq(0, stream_full_write(fds[1], bytes, 13));
	ck_assert_uint_eq(1, read_tasks(&sk, &tasks, &now));

	ck_1st_task(&tasks, &sk, "3333", "444");
	ck_assert(LIST_EMPTY(&tasks));

	printf("Read yields 1.5 requests\n");
	encode_request("55", "666", bytes); /* 11 bytes */
	ck_assert_int_eq(0, stream_full_write(fds[1], bytes, 11));
	encode_request("777", "88", bytes); /* 11 bytes */
	ck_assert_int_eq(0, stream_full_write(fds[1], bytes, 5));
	ck_assert_uint_eq(1, read_tasks(&sk, &tasks, &now));

	ck_1st_task(&tasks, &sk, "55", "666");
	ck_assert(LIST_EMPTY(&tasks));

	ck_assert_int_eq(0, stream_full_write(fds[1], bytes + 5, 6));
	ck_assert_uint_eq(1, read_tasks(&sk, &tasks, &now));

	ck_1st_task(&tasks, &sk, "777", "88");
	ck_assert(LIST_EMPTY(&tasks));

	printf("Read yields 2 requests\n");
	encode_request("9999", "00", bytes); /* 12 bytes */
	ck_assert_int_eq(0, stream_full_write(fds[1], bytes, 12));
	encode_request("aa", "bbbb", bytes); /* 12 bytes */
	ck_assert_int_eq(0, stream_full_write(fds[1], bytes, 12));
	ck_assert_uint_eq(2, read_tasks(&sk, &tasks, &now));
	ck_1st_task(&tasks, &sk, "aa", "bbbb");
	ck_1st_task(&tasks, &sk, "9999", "00");
	ck_assert(LIST_EMPTY(&tasks));

	printf("Read yields 2.5 requests\n");
	encode_request("cc", "dd", bytes); /* 10 bytes */
	ck_assert_int_eq(0, stream_full_write(fds[1], bytes, 10));
	encode_request("eeeee", "fffff", bytes); /* 16 bytes */
	ck_assert_int_eq(0, stream_full_write(fds[1], bytes, 16));
	encode_request("gggg", "hhhhh", bytes); /* 15 bytes */
	ck_assert_int_eq(0, stream_full_write(fds[1], bytes, 3));

	ck_assert_uint_eq(2, read_tasks(&sk, &tasks, &now));
	ck_1st_task(&tasks, &sk, "eeeee", "fffff");
	ck_1st_task(&tasks, &sk, "cc", "dd");
	ck_assert(LIST_EMPTY(&tasks));

	ck_assert_int_eq(0, stream_full_write(fds[1], bytes + 3, 12));
	ck_assert_uint_eq(1, read_tasks(&sk, &tasks, &now));
	ck_1st_task(&tasks, &sk, "gggg", "hhhhh");
	ck_assert(LIST_EMPTY(&tasks));
}
END_TEST

static void
wait_rsyncs(unsigned int count)
{
	unsigned int done = 0;

	do {
		sleep(1);
		done += rsync_finished();
		printf("rsyncs done: %u\n", done);
	} while (done < count);

	ck_assert_uint_eq(count, done);
}

START_TEST(test_fast_single_rsync)
{
	rsync_setup("resources/rsync/fast.sh", NULL);
	ck_assert_int_ne(-1, readfd);
	ck_assert_int_ne(-1, writefd);

	ck_assert_int_eq(0, rsync_queue("A", "B"));
	wait_rsyncs(1);

	rsync_teardown();
}
END_TEST

START_TEST(test_stalled_single_rsync)
{
	rsync_setup("resources/rsync/stalled.sh", NULL);
	ck_assert_int_ne(-1, readfd);
	ck_assert_int_ne(-1, writefd);

	ck_assert_int_eq(0, rsync_queue("A", "B"));
	wait_rsyncs(1);

	rsync_teardown();
}
END_TEST

START_TEST(test_stalled_single_rsync_timeout)
{
	rsync_setup("resources/rsync/stalled-timeout.sh", NULL);
	ck_assert_int_ne(-1, readfd);
	ck_assert_int_ne(-1, writefd);

	ck_assert_int_eq(0, rsync_queue("A", "B"));
	wait_rsyncs(1);

	rsync_teardown();
}
END_TEST

START_TEST(test_dripfeed_single_rsync)
{
	rsync_setup("resources/rsync/drip-feed.sh", NULL);
	ck_assert_int_ne(-1, readfd);
	ck_assert_int_ne(-1, writefd);

	ck_assert_int_eq(0, rsync_queue("A", "B"));
	wait_rsyncs(1);

	rsync_teardown();
}
END_TEST

START_TEST(test_dripfeed_single_rsync_timeout)
{
	rsync_setup("resources/rsync/drip-feed-timeout.sh", NULL);
	ck_assert_int_ne(-1, readfd);
	ck_assert_int_ne(-1, writefd);

	ck_assert_int_eq(0, rsync_queue("A", "B"));
	wait_rsyncs(1);

	rsync_teardown();
}
END_TEST

START_TEST(test_no_rsyncs)
{
	rsync_setup("rsync", NULL);
	ck_assert_int_ne(-1, readfd);
	ck_assert_int_ne(-1, writefd);

	sleep(2);

	rsync_teardown();
}
END_TEST

START_TEST(test_simultaneous_rsyncs)
{
	create_rsync_sandbox();
	/* Note... --bwlimit does not seem to exist in openrsync */
	rsync_setup("rsync", "--bwlimit=1K", "-vvv", NULL);
	ck_assert_int_ne(-1, readfd);
	ck_assert_int_ne(-1, writefd);

	ck_assert_int_eq(0, rsync_queue("tmp/rsync/src/a", "tmp/rsync/dst/a"));
	ck_assert_int_eq(0, rsync_queue("tmp/rsync/src/b", "tmp/rsync/dst/b"));
	ck_assert_int_eq(0, rsync_queue("tmp/rsync/src/c", "tmp/rsync/dst/c"));
	wait_rsyncs(3);

	rsync_teardown();

	diff("tmp/rsync/src/a", "tmp/rsync/dst/a");
	diff("tmp/rsync/src/b", "tmp/rsync/dst/b");
	diff("tmp/rsync/src/c", "tmp/rsync/dst/c");
}
END_TEST

static Suite *
create_suite(void)
{
	Suite *suite;
	TCase *p2s, *s2r, *spawner;

	p2s = tcase_create("parent-spawner channel");
	tcase_add_test(p2s, test_decode_extremely_fragmented);
	tcase_add_test(p2s, test_read_tasks);

	s2r = tcase_create("spawner-rsync channel");
	tcase_add_test(p2s, test_fast_single_rsync);
	tcase_add_test(p2s, test_stalled_single_rsync);
	tcase_add_test(p2s, test_stalled_single_rsync_timeout);
	tcase_add_test(p2s, test_dripfeed_single_rsync);
	tcase_add_test(p2s, test_dripfeed_single_rsync_timeout);
	tcase_set_timeout(p2s, 6);

	spawner = tcase_create("spawner");
	tcase_add_test(spawner, test_no_rsyncs);
	tcase_add_test(spawner, test_simultaneous_rsyncs);
	tcase_set_timeout(spawner, 6);

	suite = suite_create("rsync");
	suite_add_tcase(suite, p2s);
	suite_add_tcase(suite, s2r);
	suite_add_tcase(suite, spawner);

	return suite;
}

int
main(void)
{
	SRunner *runner;
	int tests_failed;

	printf("This test needs to exhaust some timeouts. Please be patient.\n");
	disable_sigpipe();
	init_content();

	runner = srunner_create(create_suite());
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
