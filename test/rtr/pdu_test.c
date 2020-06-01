#include <check.h>
#include <stdio.h>
#include <unistd.h>

#include "common.c"
#include "log.c"
#include "impersonator.c"
#include "rtr/stream.c"
#include "rtr/err_pdu.c"
#include "rtr/pdu.c"
#include "rtr/primitive_reader.c"
#include "rtr/db/rtr_db_impersonator.c"

/*
 * Just a wrapper for `buffer2fd()`. Boilerplate one-liner.
 */
#define BUFFER2FD(buffer, cb, obj) {					\
	struct pdu_header header;					\
	struct pdu_reader reader;					\
	unsigned char read[sizeof(buffer)];				\
	int fd, err;							\
									\
	fd = buffer2fd(buffer, sizeof(buffer));				\
	ck_assert_int_ge(fd, 0);					\
	ck_assert_int_eq(pdu_reader_init(&reader, fd, read,		\
	    sizeof(buffer), true), 0);					\
	close(fd);							\
	init_pdu_header(&header);					\
	err = cb(&header, &reader, obj);				\
	ck_assert_int_eq(err, 0);					\
	assert_pdu_header(&(obj)->header);				\
}

/* Impersonator functions */

#define IMPERSONATE_HANDLER(name)					\
	int								\
	handle_## name ##_pdu(int fd, struct rtr_request const *req) {	\
		return 0;						\
	}

uint16_t
get_current_session_id(uint8_t rtr_version)
{
	return 12345;
}

int
clients_set_rtr_version(int fd, uint8_t rtr_version)
{
	return 0;
}

int
clients_get_rtr_version_set(int fd, bool *is_set, uint8_t *rtr_version)
{
	(*is_set) = true;
	(*rtr_version) = RTR_V0;
	return 0;
}

IMPERSONATE_HANDLER(serial_notify)
IMPERSONATE_HANDLER(serial_query)
IMPERSONATE_HANDLER(reset_query)
IMPERSONATE_HANDLER(cache_response)
IMPERSONATE_HANDLER(ipv4_prefix)
IMPERSONATE_HANDLER(ipv6_prefix)
IMPERSONATE_HANDLER(end_of_data)
IMPERSONATE_HANDLER(cache_reset)
IMPERSONATE_HANDLER(router_key)
IMPERSONATE_HANDLER(error_report)

int
send_error_report_pdu(int fd, uint8_t version, uint16_t code,
    struct rtr_request const *request, char *message)
{
	pr_op_info("    Server sent Error Report %u: '%s'", code, message);
	return 0;
}

int
rtrhandler_handle_roa_v4(struct db_table *table, uint32_t asn,
    struct ipv4_prefix const *prefix4, uint8_t max_length)
{
	return 0;
}

int
rtrhandler_handle_roa_v6(struct db_table *table, uint32_t asn,
    struct ipv6_prefix const *prefix6, uint8_t max_length)
{
	return 0;
}

int
rtrhandler_handle_router_key(struct db_table *table,
    unsigned char const *ski, uint32_t as, unsigned char const *spk)
{
	return 0;
}

/* End of impersonator */

static void
init_pdu_header(struct pdu_header *header)
{
	header->protocol_version = RTR_V0;
	header->pdu_type = 22;
	header->m.reserved = get_current_session_id(RTR_V0);
	header->length = 0x00000020;
}

static void
assert_pdu_header(struct pdu_header *header)
{
	ck_assert_uint_eq(header->protocol_version, 0);
	ck_assert_uint_eq(header->pdu_type, 22);
	ck_assert_uint_eq(header->m.reserved, get_current_session_id(RTR_V0));
	ck_assert_uint_eq(header->length, 0x00000020);
}

START_TEST(test_pdu_header_from_stream)
{
	unsigned char input[] = { 0, 1, 2, 3, 4, 5, 6, 7 };
	unsigned char read[RTRPDU_HDR_LEN];
	struct pdu_reader reader;
	struct pdu_header header;
	int fd;
	int err;

	fd = buffer2fd(input, sizeof(input));
	ck_assert_int_ge(fd, 0);
	ck_assert_int_eq(pdu_reader_init(&reader, fd, read, RTRPDU_HDR_LEN,
	    true), 0);
	close(fd);
	/* Read the header into its buffer. */
	err = pdu_header_from_reader(&reader, &header);
	ck_assert_int_eq(err, 0);

	ck_assert_uint_eq(header.protocol_version, 0);
	ck_assert_uint_eq(header.pdu_type, 1);
	ck_assert_uint_eq(header.m.reserved, 0x0203);
	ck_assert_uint_eq(header.length, 0x04050607);
}
END_TEST

START_TEST(test_serial_notify_from_stream)
{
	unsigned char input[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
	struct serial_notify_pdu pdu;

	BUFFER2FD(input, serial_notify_from_stream, &pdu);
	ck_assert_uint_eq(pdu.serial_number, 0x010203);
}
END_TEST

START_TEST(test_serial_query_from_stream)
{
	unsigned char input[] = { 13, 14, 15, 16, 17 };
	struct serial_query_pdu pdu;

	BUFFER2FD(input, serial_query_from_stream, &pdu);
	ck_assert_uint_eq(pdu.serial_number, 0x0d0e0f10);
}
END_TEST

START_TEST(test_reset_query_from_stream)
{
	unsigned char input[] = { 18, 19 };
	struct reset_query_pdu pdu;

	BUFFER2FD(input, reset_query_from_stream, &pdu);
}
END_TEST

START_TEST(test_cache_response_from_stream)
{
	unsigned char input[] = { 18, 19 };
	struct cache_response_pdu pdu;

	BUFFER2FD(input, cache_response_from_stream, &pdu);
}
END_TEST

START_TEST(test_ipv4_prefix_from_stream)
{
	unsigned char input[] = { 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
			29, 30, 31, 32 };
	struct ipv4_prefix_pdu pdu;

	BUFFER2FD(input, ipv4_prefix_from_stream, &pdu);
	ck_assert_uint_eq(pdu.flags, 18);
	ck_assert_uint_eq(pdu.prefix_length, 19);
	ck_assert_uint_eq(pdu.max_length, 20);
	ck_assert_uint_eq(pdu.zero, 21);
	ck_assert_uint_eq(pdu.ipv4_prefix.s_addr, 0x16171819);
	ck_assert_uint_eq(pdu.asn, 0x1a1b1c1d);
}
END_TEST

START_TEST(test_ipv6_prefix_from_stream)
{
	unsigned char input[] = { 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
			44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
			58, 59, 60 };
	struct ipv6_prefix_pdu pdu;
	struct in6_addr tmp;

	BUFFER2FD(input, ipv6_prefix_from_stream, &pdu);
	ck_assert_uint_eq(pdu.flags, 33);
	ck_assert_uint_eq(pdu.prefix_length, 34);
	ck_assert_uint_eq(pdu.max_length, 35);
	ck_assert_uint_eq(pdu.zero, 36);
	in6_addr_init(&tmp, 0x25262728, 0x292a2b2c, 0x2d2e2f30, 0x31323334);
	ck_assert(IN6_ARE_ADDR_EQUAL(&tmp, &pdu.ipv6_prefix));
	ck_assert_uint_eq(pdu.asn, 0x35363738);
}
END_TEST

START_TEST(test_end_of_data_from_stream)
{
	unsigned char input[] = { 61, 62, 63, 64 };
	struct end_of_data_pdu pdu;

	BUFFER2FD(input, end_of_data_from_stream, &pdu);
	ck_assert_uint_eq(pdu.serial_number, 0x3d3e3f40);
}
END_TEST

START_TEST(test_cache_reset_from_stream)
{
	unsigned char input[] = { 65, 66, 67 };
	struct cache_reset_pdu pdu;

	BUFFER2FD(input, cache_reset_from_stream, &pdu);
}
END_TEST

START_TEST(test_error_report_from_stream)
{
	unsigned char input[] = {
			/* Sub-pdu length */
			0, 0, 0, 12,
			/* Sub-pdu w header*/
			1, 0, 2, 3, 0, 0, 0, 12, 1, 2, 3, 4,
			/* Error msg length */
			0, 0, 0, 5,
			/* Error msg */
			'h', 'e', 'l', 'l', 'o',
			/* Garbage */
			1, 2, 3, 4,
	};
	struct error_report_pdu *pdu;
	struct serial_notify_pdu *sub_pdu;
	struct pdu_header sub_pdu_header;
	struct pdu_reader reader;
	unsigned char sub_pdu_read[12];
	int fd, err;

	pdu = malloc(sizeof(struct error_report_pdu));
	if (!pdu)
		ck_abort_msg("PDU allocation failure");

	sub_pdu = malloc(sizeof(struct serial_notify_pdu));
	if (!sub_pdu) {
		ck_abort_msg("SUB PDU allocation failure");
		free(pdu);
	}

	BUFFER2FD(input, error_report_from_stream, pdu);

	/* Get the erroneous PDU as a serial notify */
	fd = buffer2fd(pdu->erroneous_pdu, pdu->error_pdu_length);
	ck_assert_int_ge(fd, 0);
	ck_assert_int_eq(pdu_reader_init(&reader, fd, sub_pdu_read,
	    pdu->error_pdu_length, true), 0);
	close(fd);

	ck_assert_int_eq(pdu_header_from_reader(&reader, &sub_pdu_header), 0);
	err = serial_notify_from_stream(&sub_pdu_header, &reader, sub_pdu);
	ck_assert_int_eq(err, 0);

	ck_assert_uint_eq(sub_pdu->header.protocol_version, 1);
	ck_assert_uint_eq(sub_pdu->header.pdu_type, 0);
	ck_assert_uint_eq(sub_pdu->header.m.reserved, 0x0203);
	ck_assert_uint_eq(sub_pdu->header.length, 12);
	ck_assert_uint_eq(sub_pdu->serial_number, 0x01020304);
	ck_assert_str_eq(pdu->error_message, "hello");

	/*
	 * Yes, this test memory leaks on failure.
	 * Not sure how to fix it without making a huge mess.
	 */
	error_report_destroy(pdu);
	free(sub_pdu);
}
END_TEST

START_TEST(test_interrupted)
{
	unsigned char input[] = { 0, 1 };
	struct pdu_reader reader;
	unsigned char read[4];
	int fd, err;

	fd = buffer2fd(input, sizeof(input));
	ck_assert_int_ge(fd, 0);
	err = pdu_reader_init(&reader, fd, read, 4, true);
	close(fd);
	ck_assert_int_eq(err, -EPIPE);
}
END_TEST

Suite *pdu_suite(void)
{
	Suite *suite;
	TCase *core, *errors;

	core = tcase_create("Core");
	tcase_add_test(core, test_pdu_header_from_stream);
	tcase_add_test(core, test_serial_notify_from_stream);
	tcase_add_test(core, test_serial_notify_from_stream);
	tcase_add_test(core, test_serial_query_from_stream);
	tcase_add_test(core, test_reset_query_from_stream);
	tcase_add_test(core, test_cache_response_from_stream);
	tcase_add_test(core, test_ipv4_prefix_from_stream);
	tcase_add_test(core, test_ipv6_prefix_from_stream);
	tcase_add_test(core, test_end_of_data_from_stream);
	tcase_add_test(core, test_cache_reset_from_stream);
	tcase_add_test(core, test_error_report_from_stream);

	errors = tcase_create("Errors");
	tcase_add_test(errors, test_interrupted);

	suite = suite_create("PDU");
	suite_add_tcase(suite, core);
	suite_add_tcase(suite, errors);
	return suite;
}

int main(void)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	suite = pdu_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
