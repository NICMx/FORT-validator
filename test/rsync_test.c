#include <check.h>

#include "alloc.c"
#include "common.c"
#include "mock.c"
#include "rsync.c"
#include "stream.c"
#include "types/map.c"
#include "types/url.c"

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
MOCK_UINT(config_rsync_max, 3, void)
MOCK(config_rsync_timeout, long, 4, void)
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

static struct timespec rsync_request_time;
static int rsync_expected_duration = -1;
static int rsyncs_done = 0;

void
rsync_finished(struct uri const *url, char const *path)
{
	struct timespec now;
	int delta;

	if (rsync_expected_duration == -1)
		ck_abort_msg("rsync_finished() called, but duration not set.");

	ts_now(&now);
	delta = ts_delta(&rsync_request_time, &now);

	printf("Callback! rsync finished after %dms.\n", delta);
	if (rsync_expected_duration < 100)
		ck_assert_int_le(0, delta);
	else
		ck_assert_int_le(rsync_expected_duration - 100, delta);
	ck_assert_int_lt(delta, rsync_expected_duration + 100);

	rsyncs_done++;
}

/* Tests */

/* Test RsyncRequest decode, feeding as few bytes as possible every time. */
START_TEST(test_decode_extremely_fragmented)
{
	struct uri uri;
	struct RsyncRequest src, *dst;
	unsigned char encoded[BUFSIZE];
	asn_enc_rval_t encres;
	asn_dec_rval_t decres;
	unsigned int start, end, max;

	__URI_INIT(&uri, "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789");

	ck_assert_int_eq(0, RsyncRequest_init(&src, &uri,
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
ck_no_tasks(void)
{
	struct cache_mapping map;
	int error;

	error = next_task(&map);
	ck_assert(error == EAGAIN || error == EWOULDBLOCK);
}

static void
ck_next_task(char const *url, char const *path)
{
	struct cache_mapping map;

	ck_assert_int_eq(0, next_task(&map));
	ck_assert_uri(url, &map.url);
	ck_assert_str_eq(path, map.path);

	map_cleanup(&map);
}

static void
encode_request(char const *url, char const *path, unsigned char *buffer)
{
	struct uri uri;
	struct RsyncRequest rr;
	asn_enc_rval_t encres;

	__URI_INIT(&uri, url);

	ck_assert_int_eq(0, RsyncRequest_init(&rr, &uri, path));
	encres = der_encode_to_buffer(&asn_DEF_RsyncRequest, &rr, buffer, BUFSIZE);
	ck_assert_int_gt(encres.encoded, 0);
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RsyncRequest, &rr);
}

/*
 * Tests messy request queuing; in particular, when a single read() yields less
 * than one or multiple of them.
 */
START_TEST(test_next_task)
{
	unsigned char bytes[BUFSIZE];
	int fds[2];

	ck_assert_int_eq(0, nonblock_pipe(fds));
	__spsk_init(fds[RDFD], -1);

	printf("Read yields nothing\n");
	ck_no_tasks();

	printf("Read yields less than 1 request\n");
	encode_request("111", "2222", bytes); /* 13 bytes */

	ck_assert_int_eq(0, stream_full_write(fds[WRFD], bytes, 10));
	ck_no_tasks();

	ck_assert_int_eq(0, stream_full_write(fds[WRFD], bytes + 10, 3));
	ck_next_task("111", "2222");
	ck_no_tasks();

	printf("Read yields 1 request\n");
	encode_request("3333", "444", bytes); /* 13 bytes */

	ck_assert_int_eq(0, stream_full_write(fds[WRFD], bytes, 13));
	ck_next_task("3333", "444");
	ck_no_tasks();

	printf("Read yields 1.5 requests\n");
	encode_request("55", "666", bytes); /* 11 bytes */
	ck_assert_int_eq(0, stream_full_write(fds[WRFD], bytes, 11));
	encode_request("777", "88", bytes); /* 11 bytes */
	ck_assert_int_eq(0, stream_full_write(fds[WRFD], bytes, 5));

	ck_next_task("55", "666");
	ck_no_tasks();

	ck_assert_int_eq(0, stream_full_write(fds[WRFD], bytes + 5, 6));
	ck_next_task("777", "88");
	ck_no_tasks();

	printf("Read yields 2 requests\n");
	encode_request("9999", "00", bytes); /* 12 bytes */
	ck_assert_int_eq(0, stream_full_write(fds[WRFD], bytes, 12));
	encode_request("aa", "bbbb", bytes); /* 12 bytes */
	ck_assert_int_eq(0, stream_full_write(fds[WRFD], bytes, 12));

	ck_next_task("9999", "00");
	ck_next_task("aa", "bbbb");
	ck_no_tasks();

	printf("Read yields 2.5 requests\n");
	encode_request("cc", "dd", bytes); /* 10 bytes */
	ck_assert_int_eq(0, stream_full_write(fds[WRFD], bytes, 10));
	encode_request("eeeee", "fffff", bytes); /* 16 bytes */
	ck_assert_int_eq(0, stream_full_write(fds[WRFD], bytes, 16));
	encode_request("gggg", "hhhhh", bytes); /* 15 bytes */
	ck_assert_int_eq(0, stream_full_write(fds[WRFD], bytes, 3));

	ck_next_task("cc", "dd");
	ck_next_task("eeeee", "fffff");
	ck_no_tasks();

	ck_assert_int_eq(0, stream_full_write(fds[WRFD], bytes + 3, 12));
	ck_next_task("gggg", "hhhhh");
	ck_no_tasks();

	spsk_cleanup();
}
END_TEST

static int
RSYNC_QUEUE(char const *a, char const *b)
{
	struct uri uri;
	__URI_INIT(&uri, a);
	return rsync_queue(&uri, b);
}

/* Makes sure @count rsyncs finish after roughly @millis milliseconds. */
static void
wait_rsyncs(unsigned int count, unsigned int millis)
{
	struct timespec req;

	printf("Waiting for %u rsyncs after %ums.\n", count, millis);

	ts_now(&rsync_request_time);
	rsync_expected_duration = millis;
	rsyncs_done = 0;

	millis += 100;
	req.tv_sec = millis / 1000;
	req.tv_nsec = (millis % 1000) * 1000000;
	ck_assert_int_eq(0, nanosleep(&req, NULL)); /* Wait for rsync_finished() */

	ck_assert_int_eq(count, rsyncs_done);
	rsync_expected_duration = -1;
}

START_TEST(test_fast_single_rsync)
{
	printf("-- test_fast_single_rsync() --\n");

	rsync_setup("resources/rsync/fast.sh", NULL);
	ck_assert_int_ne(-1, pssk.rd.fd);
	ck_assert_int_ne(-1, pssk.wr);

	ck_assert_int_eq(0, RSYNC_QUEUE("A", "B"));
	wait_rsyncs(1, 0);

	rsync_teardown();
}
END_TEST

START_TEST(test_stalled_single_rsync)
{
	printf("-- test_stalled_single_rsync() --\n");

	rsync_setup("resources/rsync/stalled.sh", NULL);
	ck_assert_int_ne(-1, pssk.rd.fd);
	ck_assert_int_ne(-1, pssk.wr);

	ck_assert_int_eq(0, RSYNC_QUEUE("A", "B"));
	wait_rsyncs(1, 3000);

	rsync_teardown();
}
END_TEST

START_TEST(test_stalled_single_rsync_timeout)
{
	printf("-- test_stalled_single_rsync_timeout() --\n");

	rsync_setup("resources/rsync/stalled-timeout.sh", NULL);
	ck_assert_int_ne(-1, pssk.rd.fd);
	ck_assert_int_ne(-1, pssk.wr);

	ck_assert_int_eq(0, RSYNC_QUEUE("A", "B"));
	wait_rsyncs(1, 4000); /* 4000 = timeout */

	rsync_teardown();
}
END_TEST

START_TEST(test_dripfeed_single_rsync)
{
	printf("-- test_dripfeed_single_rsync() --\n");

	rsync_setup("resources/rsync/drip-feed.sh", NULL);
	ck_assert_int_ne(-1, pssk.rd.fd);
	ck_assert_int_ne(-1, pssk.wr);

	ck_assert_int_eq(0, RSYNC_QUEUE("A", "B"));
	wait_rsyncs(1, 3000);

	rsync_teardown();
}
END_TEST

START_TEST(test_dripfeed_single_rsync_timeout)
{
	printf("-- test_dripfeed_single_rsync_timeout() --\n");

	rsync_setup("resources/rsync/drip-feed-timeout.sh", NULL);
	ck_assert_int_ne(-1, pssk.rd.fd);
	ck_assert_int_ne(-1, pssk.wr);

	ck_assert_int_eq(0, RSYNC_QUEUE("A", "B"));
	wait_rsyncs(1, 4000); /* 4000 = timeout */

	rsync_teardown();
}
END_TEST

START_TEST(test_no_rsyncs)
{
	printf("-- test_no_rsyncs() --\n");

	rsync_setup("rsync", NULL);
	ck_assert_int_ne(-1, pssk.rd.fd);
	ck_assert_int_ne(-1, pssk.wr);

	wait_rsyncs(0, 2000);

	rsync_teardown();
}
END_TEST

START_TEST(test_simultaneous_rsyncs)
{
	printf("-- test_simultaneous_rsyncs() --\n");

	rsync_setup("resources/rsync/simultaneous.sh", NULL);
	ck_assert_int_ne(-1, pssk.rd.fd);
	ck_assert_int_ne(-1, pssk.wr);

	ck_assert_int_eq(0, RSYNC_QUEUE("A", "B"));
	ck_assert_int_eq(0, RSYNC_QUEUE("C", "D"));
	ck_assert_int_eq(0, RSYNC_QUEUE("E", "F"));

	wait_rsyncs(3, 1000);

	rsync_teardown();
}
END_TEST

START_TEST(test_queued_rsyncs)
{
	printf("-- test_queued_rsyncs() --\n");

	rsync_setup("resources/rsync/queued.sh", NULL);
	ck_assert_int_ne(-1, pssk.rd.fd);
	ck_assert_int_ne(-1, pssk.wr);

	ck_assert_int_eq(0, RSYNC_QUEUE("A", "B"));
	ck_assert_int_eq(0, RSYNC_QUEUE("C", "D"));
	ck_assert_int_eq(0, RSYNC_QUEUE("E", "F"));
	ck_assert_int_eq(0, RSYNC_QUEUE("G", "H"));

	wait_rsyncs(3, 2000);
	/* 2k minus the 100 extra we slept during the previous wait_rsyncs() */
	wait_rsyncs(1, 1900);

	rsync_teardown();
}
END_TEST

static Suite *
create_suite(void)
{
	Suite *suite;
	TCase *p2s, *s2r, *spawner;

	p2s = tcase_create("parent-spawner channel");
	tcase_add_test(p2s, test_decode_extremely_fragmented);
	tcase_add_test(p2s, test_next_task);

	s2r = tcase_create("spawner-rsync channel");
	tcase_add_test(s2r, test_fast_single_rsync);
	tcase_add_test(s2r, test_stalled_single_rsync);
	tcase_add_test(s2r, test_stalled_single_rsync_timeout);
	tcase_add_test(s2r, test_dripfeed_single_rsync);
	tcase_add_test(s2r, test_dripfeed_single_rsync_timeout);
	tcase_set_timeout(s2r, 6);

	spawner = tcase_create("spawner");
	tcase_add_test(spawner, test_no_rsyncs);
	tcase_add_test(spawner, test_simultaneous_rsyncs);
	tcase_add_test(spawner, test_queued_rsyncs);
	tcase_set_timeout(spawner, 5);

	suite = suite_create("rsync");
	suite_add_tcase(suite, p2s);
	suite_add_tcase(suite, s2r);
	suite_add_tcase(suite, spawner);

	return suite;
}

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
