#include <check.h>
#include <unistd.h>
#include <fcntl.h>

#include "alloc.c"
#include "mock.c"
#include "rtr/pdu_stream.c"

/* Mocks */

MOCK_ABORT_INT(err_pdu_send_invalid_request, int fd, uint8_t version,
    struct rtr_buffer const *request, char const *msg)
MOCK_ABORT_INT(err_pdu_send_unsupported_proto_version, int fd, uint8_t version,
    struct rtr_buffer const *request, char const *msg)
MOCK_ABORT_INT(err_pdu_send_unsupported_pdu_type, int fd, uint8_t version,
    struct rtr_buffer const *request)
MOCK_ABORT_INT(err_pdu_send_unexpected_proto_version, int fd, uint8_t version,
    struct rtr_buffer const *request, char const *msg)

char const *
err_pdu_to_string(uint16_t c)
{
	ck_assert_uint_eq(c, 0x1617);
	return "achoo";
}

/* End of mocks */

static void
setup_pipes(int *pipes)
{
	int fl;

	ck_assert_int_eq(0, pipe(pipes));
	fl = fcntl(pipes[0], F_GETFL);
	ck_assert_int_ne(-1, fl);
	ck_assert_int_eq(0, fcntl(pipes[0], F_SETFL, fl | O_NONBLOCK));
}

static struct pdu_stream *
create_stream(unsigned char const *buf, size_t bufsize)
{
	struct pdu_stream *result = pdustream_create(-1, "192.0.2.1");
	memcpy(result->buffer, buf, bufsize);
	result->end = result->buffer + bufsize;
	return result;
}

static struct pdu_stream *
create_stream_fd(unsigned char *data, size_t datalen, int rtr_version)
{
	struct pdu_stream *result;
	int pipes[2];

	setup_pipes(pipes);
	ck_assert_int_eq(datalen, write(pipes[1], data, datalen));
	close(pipes[1]);

	result = pdustream_create(pipes[0], "192.0.2.1");
	result->rtr_version = rtr_version;
	return result;
}

START_TEST(test_pdu_header_from_stream)
{
	unsigned char input[] = { 0, 1, 2, 3, 4, 5, 6, 7 };
	struct pdu_stream *stream;
	struct pdu_header hdr;

	stream = create_stream(input, sizeof(input));

	read_hdr(stream, &hdr);
	ck_assert_uint_eq(hdr.version, 0);
	ck_assert_uint_eq(hdr.type, 1);
	ck_assert_uint_eq(hdr.m.reserved, 0x0203);
	ck_assert_uint_eq(hdr.len, 0x04050607);

	free(stream);
}
END_TEST

START_TEST(test_serial_query_from_stream)
{
	unsigned char input[] = {
		/* header */
		1, 1, 7, 8, 0, 0, 0, 12,
		/* serial number */
		14, 15, 16, 17,
	};
	struct pdu_stream *stream;
	struct rtr_request *request;

	stream = create_stream_fd(input, sizeof(input), RTR_V1);
	ck_assert_uint_eq(true, pdustream_next(stream, &request));

	ck_assert_int_eq(stream->fd, request->fd);
	ck_assert_str_eq(stream->addr, request->client_addr);
	ck_assert_uint_eq(RTR_V1, request->pdu.rtr_version);
	ck_assert_uint_eq(PDU_TYPE_SERIAL_QUERY, request->pdu.type);
	ck_assert_uint_eq(0x0e0f1011, request->pdu.obj.sq.serial_number);
	ck_assert_uint_eq(0x0708, request->pdu.obj.sq.session_id);
	ck_assert_uint_eq(12, request->pdu.raw.bytes_len);
	ck_assert(memcmp(input, request->pdu.raw.bytes, 12) == 0);
	ck_assert_uint_eq(1, request->eos);

	rtreq_destroy(request);
	pdustream_destroy(&stream);
}
END_TEST

START_TEST(test_reset_query_from_stream)
{
	unsigned char input[] = {
		/* Header  */ 0, 2, 12, 13, 0, 0, 0, 8,
		/* Garbage */ 18, 19,
	};
	struct pdu_stream *stream;
	struct rtr_request *request;

	stream = create_stream_fd(input, sizeof(input), RTR_V0);
	ck_assert_uint_eq(true, pdustream_next(stream, &request));
	ck_assert_int_eq(stream->fd, request->fd);
	ck_assert_str_eq(stream->addr, request->client_addr);
	ck_assert_uint_eq(RTR_V0, request->pdu.rtr_version);
	ck_assert_uint_eq(PDU_TYPE_RESET_QUERY, request->pdu.type);
	ck_assert_uint_eq(8, request->pdu.raw.bytes_len);
	ck_assert(memcmp(input, request->pdu.raw.bytes, 8) == 0);
	ck_assert_uint_eq(1, request->eos);

	rtreq_destroy(request);
	pdustream_destroy(&stream);
}
END_TEST

START_TEST(test_error_report_from_stream)
{
	unsigned char input[] = {
		/* header */
		1, 10, 22, 23, 0, 0, 0, 33,
		/* Sub-pdu length */
		0, 0, 0, 12,
		/* Sub-pdu with header*/
		1, 0, 2, 3, 0, 0, 0, 12, 1, 2, 3, 4,
		/* Error msg length */
		0, 0, 0, 5,
		/* Error msg */
		'h', 'e', 'l', 'l', 'o',
		/* Garbage */
		1, 2, 3, 4,
	};
	struct pdu_stream *stream;
	struct rtr_request *request;

	stream = create_stream_fd(input, sizeof(input), RTR_V1);
	ck_assert_uint_eq(false, pdustream_next(stream, &request));
	ck_assert_ptr_eq(NULL, request);
	pdustream_destroy(&stream);
}
END_TEST

#define ASSERT_RQ(_req, _version)					\
	ck_assert_uint_eq(_req->pdu.rtr_version, _version);		\
	ck_assert_uint_eq(_req->pdu.type, PDU_TYPE_RESET_QUERY);

#define ASSERT_SQ(_req, _version, _type, _session, _serial)		\
	ck_assert_uint_eq(_req->pdu.rtr_version, _version);		\
	ck_assert_uint_eq(_req->pdu.type, PDU_TYPE_SERIAL_QUERY);	\
	ck_assert_uint_eq(_req->pdu.obj.sq.session_id, _session);	\
	ck_assert_uint_eq(_req->pdu.obj.sq.serial_number, _serial);

START_TEST(test_multiple_pdus)
{
	unsigned char input1[] = {
		/* reset query */	1, 2, 0, 0, 0, 0, 0, 8,
		/* serial query */	1, 1, 0, 0, 0, 0, 0, 12, 1, 2, 3, 4,
		/* reset query */	1, 2, 3, 4, 0, 0, 0, 8,
		/* reset query start */	1, 2, 3, 4,
	};
	unsigned char input2[] = {
		/* reset query end */	0, 0, 0, 8,
		/* reset query */	1, 2, 6, 7, 0, 0, 0, 8,
	};
	struct pdu_stream *stream;
	struct rtr_request *request;
	int pipes[2];

	setup_pipes(pipes);

	stream = pdustream_create(pipes[0], "192.0.2.1");

	/* Input 1 */

	ck_assert_int_eq(32, write(pipes[1], input1, sizeof(input1)));
	ck_assert_uint_eq(true, pdustream_next(stream, &request));

	ck_assert_int_eq(stream->fd, request->fd);
	ck_assert_str_eq(stream->addr, request->client_addr);
	ASSERT_RQ(request, RTR_V1);
	ck_assert_uint_eq(8, request->pdu.raw.bytes_len);
	ck_assert(memcmp(input1 + 20, request->pdu.raw.bytes, 8) == 0);
	ck_assert_uint_eq(0, request->eos);

	rtreq_destroy(request);

	/* Input 2 */

	ck_assert_int_eq(12, write(pipes[1], input2, sizeof(input2)));
	ck_assert_uint_eq(true, pdustream_next(stream, &request));

	ck_assert_int_eq(stream->fd, request->fd);
	ck_assert_str_eq(stream->addr, request->client_addr);
	ASSERT_RQ(request, RTR_V1);
	ck_assert_uint_eq(8, request->pdu.raw.bytes_len);
	ck_assert(memcmp(input2 + 4,  request->pdu.raw.bytes, 8) == 0);
	ck_assert_uint_eq(0, request->eos);

	rtreq_destroy(request);

	/* Input 3 */

	close(pipes[1]);
	ck_assert_uint_eq(false, pdustream_next(stream, &request));
	ck_assert_ptr_eq(NULL, request);

	/* Clean up */

	pdustream_destroy(&stream);
}
END_TEST

START_TEST(test_interrupted)
{
	unsigned char input[] = { 0, 1 };
	struct pdu_stream *stream;
	struct rtr_request *request;

	stream = create_stream_fd(input, sizeof(input), RTR_V1);

	ck_assert_uint_eq(false, pdustream_next(stream, &request));
	ck_assert_ptr_eq(NULL, request);

	pdustream_destroy(&stream);
}
END_TEST

static void
test_read_string_success(unsigned char *input, size_t length, char *expected)
{
	struct pdu_stream *stream;
	char *actual;

	stream = create_stream(input, length);
	actual = read_string(stream, length);
	ck_assert_pstr_eq(expected, actual);

	free(actual);
	free(stream);
}

START_TEST(read_string_ascii)
{
	unsigned char input[] = { 'a', 'b', 'c', 'd' };
	test_read_string_success(input, sizeof(input), "abcd");
}
END_TEST

START_TEST(read_string_unicode)
{
	unsigned char input0[] = { 's', 'a', 'n', 'd', 0xc3, 0xad, 'a' };
	test_read_string_success(input0, sizeof(input0), "sandía");

	unsigned char input1[] = { 0xe1, 0x88, 0x90, 0xe1, 0x89, 0xa5, 0xe1,
	    0x88, 0x90, 0xe1, 0x89, 0xa5 };
	test_read_string_success(input1, sizeof(input1), "ሐብሐብ");

	unsigned char input2[] = { 0xd8, 0xa7, 0xd9, 0x84, 0xd8, 0xa8, 0xd8,
	    0xb7, 0xd9, 0x8a, 0xd8, 0xae };
	test_read_string_success(input2, sizeof(input2), "البطيخ");

	unsigned char input3[] = {
	    0xd5, 0xb1, 0xd5, 0xb4, 0xd5, 0xa5, 0xd6, 0x80, 0xd5, 0xb8, 0xd6,
	    0x82, 0xd5, 0xaf, 0x20, 0xd0, 0xba, 0xd0, 0xb0, 0xd0, 0xb2, 0xd1,
	    0x83, 0xd0, 0xbd };
	test_read_string_success(input3, sizeof(input3), "ձմերուկ кавун");

	unsigned char input4[] = {
	    0xe0, 0xa6, 0xa4, 0xe0, 0xa6, 0xb0, 0xe0, 0xa6, 0xae, 0xe0, 0xa7,
	    0x81, 0xe0, 0xa6, 0x9c, 0x20, 0xd0, 0xb4, 0xd0, 0xb8, 0xd0, 0xbd,
	    0xd1, 0x8f, 0x20, 0xe8, 0xa5, 0xbf, 0xe7, 0x93, 0x9c, 0x20, 0xf0,
	    0x9f, 0x8d, 0x89 };
	test_read_string_success(input4, sizeof(input4), "তরমুজ диня 西瓜 🍉");
}
END_TEST

START_TEST(read_string_empty)
{
	unsigned char input[] = { 0, 0, 0, 0 };
	test_read_string_success(input, sizeof(input), "");
}
END_TEST

struct thread_param {
	int	fd;
	uint32_t	msg_size;
	int	err;
};

/*
 * Sends @full_string_length characters to the fd, validates the parsed string
 * contains the first @return_length characters.
 */
START_TEST(read_string_max)
{
	static char const *STR =
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" /* 52 */
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" /* 104 */
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" /* 156 */
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" /* 208 */
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" /* 260 */
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" /* 312 */
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" /* 364 */
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" /* 416 */
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" /* 468 */
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" /* 520 */
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" /* 572 */
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" /* 624 */
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" /* 676 */
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" /* 728 */
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" /* 780 */
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" /* 832 */
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" /* 884 */
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" /* 936 */
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" /* 988 */
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"; /* 1024 */
	struct pdu_stream *stream;
	char *result_string;

	stream = create_stream((unsigned char *)STR, RTRPDU_MAX_LEN2);

	result_string = read_string(stream, RTRPDU_MAX_LEN2);
	ck_assert_int_eq(0, strcmp(STR, result_string));

	free(result_string);
	free(stream);
}
END_TEST

START_TEST(read_string_null)
{
	test_read_string_success(NULL, 0, NULL);
}
END_TEST

START_TEST(read_string_unicode_mix)
{
	/* One octet failure */
	unsigned char input0[] = { 'a', 0x80, 'z' };
	test_read_string_success(input0, sizeof(input0), "a");

	/* Two octets success */
	unsigned char input1[] = { 'a', 0xdf, 0x9a, 'z' };
	test_read_string_success(input1, sizeof(input1), "aߚz");
	/* Two octets failure */
	unsigned char input2[] = { 'a', 0xdf, 0xda, 'z' };
	test_read_string_success(input2, sizeof(input2), "a");

	/* Three characters success */
	unsigned char input3[] = { 'a', 0xe2, 0x82, 0xac, 'z' };
	test_read_string_success(input3, sizeof(input3), "a€z");
	/* Three characters failure */
	unsigned char input4[] = { 'a', 0xe2, 0x82, 0x2c, 'z' };
	test_read_string_success(input4, sizeof(input4), "a");

	/* Four characters success */
	unsigned char i5[] = { 'a', 0xf0, 0x90, 0x86, 0x97, 'z' };
	test_read_string_success(i5, sizeof(i5), "a𐆗z");
	/* Four characters failure */
	unsigned char i6[] = { 'a', 0xf0, 0x90, 0x90, 0x17, 'z' };
	test_read_string_success(i6, sizeof(i6), "a");
}
END_TEST

static Suite *create_suite(void)
{
	Suite *suite;
	TCase *core, *errors, *string;

	core = tcase_create("Core");
	tcase_add_test(core, test_pdu_header_from_stream);
	tcase_add_test(core, test_serial_query_from_stream);
	tcase_add_test(core, test_reset_query_from_stream);
	tcase_add_test(core, test_error_report_from_stream);
	tcase_add_test(core, test_multiple_pdus);

	errors = tcase_create("Errors");
	tcase_add_test(errors, test_interrupted);
	/* FIXME (RTR) test more errors */

	string = tcase_create("String");
	tcase_add_test(string, read_string_ascii);
	tcase_add_test(string, read_string_unicode);
	tcase_add_test(string, read_string_empty);
	tcase_add_test(string, read_string_max);
	tcase_add_test(string, read_string_null);
	tcase_add_test(string, read_string_unicode_mix);

	suite = suite_create("PDU stream");
	suite_add_tcase(suite, core);
	suite_add_tcase(suite, errors);
	suite_add_tcase(suite, string);
	return suite;
}

int main(void)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	suite = create_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
