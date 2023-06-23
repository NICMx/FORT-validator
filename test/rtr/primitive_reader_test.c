#include <check.h>
#include <error.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alloc.c"
#include "impersonator.c"
#include "log.c"
#include "rtr/primitive_reader.c"

/*
 * Wrapper for `read_string()`, for easy testing.
 */
static int
__read_string(unsigned char *input, size_t size, rtr_char **result)
{
	struct pdu_reader reader;
	pdu_reader_init(&reader, input, size);
	return read_string(&reader, size & 0xFFFF, result);
}

static void
test_read_string_success(unsigned char *input, size_t length,
    rtr_char *expected)
{
	rtr_char *actual;
	int err;

	err = __read_string(input, length, &actual);
	ck_assert_int_eq(0, err);
	if (!err) {
		ck_assert_str_eq(expected, actual);
		free(actual);
	}
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

#define WRITER_PATTERN "abcdefghijklmnopqrstuvwxyz0123456789"

/*
 * Checks that the string @str is made up of @expected_len characters composed
 * of the @WRITER_PATTERN pattern repeatedly.
 */
static void
validate_massive_string(uint32_t expected_len, rtr_char *str)
{
	size_t actual_len;
	rtr_char *pattern;
	size_t pattern_len;
	rtr_char *cursor;
	rtr_char *end;

	actual_len = strlen(str);
	if (expected_len != actual_len) {
		free(str);
		ck_abort_msg("Expected length %u != Actual length %zu",
		    expected_len, actual_len);
	}

	pattern = WRITER_PATTERN;
	pattern_len = strlen(pattern);
	end = str + expected_len;
	for (cursor = str; cursor + pattern_len < end; cursor += pattern_len) {
		if (strncmp(pattern, cursor, pattern_len) != 0) {
			free(str);
			ck_abort_msg("String does not match expected pattern");
		}
	}

	if (strncmp(pattern, cursor, strlen(cursor)) != 0) {
		free(str);
		ck_abort_msg("String end does not match expected pattern");
	}

	free(str);
	/* Success */
}

/*
 * Sends @full_string_length characters to the fd, validates the parsed string
 * contains the first @return_length characters.
 */
static void
test_massive_string(uint32_t return_length, uint32_t full_string_length)
{
	unsigned char *buffer;
	rtr_char *pattern;
	size_t pattern_len;

	size_t written;
	size_t w;

	struct pdu_reader reader;
	rtr_char *result_string;

	buffer = malloc(full_string_length);
	if (buffer == NULL)
		ck_abort_msg("Out of memory.");

	pattern = WRITER_PATTERN;
	pattern_len = strlen(pattern);
	for (written = 0; written < full_string_length; written += w) {
		w = (full_string_length - written > pattern_len)
		    ? pattern_len
		    : (full_string_length - written);
		memcpy(&buffer[written], pattern, w);
	}

	pdu_reader_init(&reader, buffer, full_string_length);
	ck_assert_int_eq(0, read_string(&reader, full_string_length,
	    &result_string));

	validate_massive_string(return_length, result_string);

	free(buffer);
}

START_TEST(read_string_massive)
{
	test_massive_string(2000, 2000);
	test_massive_string(4000, 4000);
	test_massive_string(4094, 4094);
	test_massive_string(4095, 4095);
	test_massive_string(4096, 4096);
	test_massive_string(4097, 4097);
	test_massive_string(8000, 8000);
	test_massive_string(16000, 16000);
}
END_TEST

START_TEST(read_string_null)
{
	test_read_string_success(NULL, 0, "");
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

Suite *read_string_suite(void)
{
	Suite *suite;
	TCase *core, *limits, *errors;

	core = tcase_create("Core");
	tcase_add_test(core, read_string_ascii);
	tcase_add_test(core, read_string_unicode);

	limits = tcase_create("Limits");
	tcase_add_test(limits, read_string_empty);
	tcase_add_test(limits, read_string_massive);

	errors = tcase_create("Errors");
	tcase_add_test(errors, read_string_null);
	tcase_add_test(errors, read_string_unicode_mix);

	suite = suite_create("read_string()");
	suite_add_tcase(suite, core);
	suite_add_tcase(suite, limits);
	suite_add_tcase(suite, errors);
	return suite;
}

int main(void)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	/*
	 * This is it. We won't test the other functions because they are
	 * already reasonably manhandled in the PDU units.
	 */
	suite = read_string_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
