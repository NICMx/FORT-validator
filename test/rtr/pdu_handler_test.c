#include <check.h>
#include <stdlib.h>
#include <sys/queue.h>

#include "validation_handler.h"
#include "rtr/pdu.h"
#include "rtr/pdu_handler.h"
#include "rtr/pdu_sender.h"
#include "rtr/db/vrps.h"

/* TODO (now) test the removal of deltas that cancel each other */
/* TODO (now) test delta forgetting */

/* Helper functions */

struct expected_pdu {
	uint8_t pdu_type;
	STAILQ_ENTRY(expected_pdu) list_hook;
};

static STAILQ_HEAD(, expected_pdu) expected_pdus = STAILQ_HEAD_INITIALIZER(expected_pdus);

static void
expected_pdu_add(uint8_t pdu_type)
{
	struct expected_pdu *pdu;

	pdu = malloc(sizeof(struct expected_pdu));
	ck_assert_ptr_ne(NULL, pdu);

	pdu->pdu_type = pdu_type;
	STAILQ_INSERT_TAIL(&expected_pdus, pdu, list_hook);
}

static uint8_t
pop_expected_pdu(void)
{
	struct expected_pdu *pdu;
	uint8_t result;

	pdu = STAILQ_FIRST(&expected_pdus);
	ck_assert_ptr_ne(NULL, pdu);
	result = pdu->pdu_type;
	STAILQ_REMOVE(&expected_pdus, pdu, expected_pdu, list_hook);
	free(pdu);

	return result;
}

static bool
has_expected_pdus(void)
{
	return !STAILQ_EMPTY(&expected_pdus);
}

static void
init_db_full(void)
{
	bool changed;
	ck_assert_int_eq(0, vrps_init());
	ck_assert_int_eq(0, vrps_update(&changed));
	ck_assert_uint_eq(true, changed);
	ck_assert_int_eq(0, vrps_update(&changed));
	ck_assert_uint_eq(true, changed);
	ck_assert_int_eq(0, vrps_update(&changed));
	ck_assert_uint_eq(true, changed);
}

static void
init_reset_query(struct reset_query_pdu *query)
{
	query->header.protocol_version = RTR_V0;
	query->header.pdu_type = PDU_TYPE_RESET_QUERY;
	query->header.m.reserved = 0;
	query->header.length = 8;
}

static void
init_serial_query(struct serial_query_pdu *query, uint32_t serial)
{
	query->header.protocol_version = RTR_V0;
	query->header.pdu_type = PDU_TYPE_SERIAL_QUERY;
	query->header.m.session_id = get_current_session_id(RTR_V0);
	query->header.length = 12;
	query->serial_number = serial;
}

/* Impersonator functions */

serial_t
clients_get_min_serial(void)
{
	return 0;
}

void
init_sender_common(struct sender_common *common, int fd, uint8_t version)
{
	common->fd = fd;
	common->version = version;
	common->session_id = get_current_session_id(version);
}

int
send_cache_reset_pdu(struct sender_common *common)
{
	pr_info("    Server sent Cache Reset.");
	ck_assert_int_eq(pop_expected_pdu(), PDU_TYPE_CACHE_RESET);
	return 0;
}

int
send_cache_response_pdu(struct sender_common *common)
{
	pr_info("    Server sent Cache Response.");
	ck_assert_int_eq(pop_expected_pdu(), PDU_TYPE_CACHE_RESPONSE);
	return 0;
}

int
send_prefix_pdu(struct sender_common *common, struct vrp const *vrp,
    uint8_t flags)
{
	/*
	 * We don't care about order.
	 * If the server is expected to return `M` IPv4 PDUs and `N` IPv6 PDUs,
	 * we'll just check `M + N` contiguous Prefix PDUs.
	 */
	uint8_t pdu_type = pop_expected_pdu();
	pr_info("    Server sent Prefix PDU.");
	ck_assert_msg(pdu_type == PDU_TYPE_IPV4_PREFIX
	    || pdu_type == PDU_TYPE_IPV6_PREFIX,
	    "Server's PDU type is %d, not one of the IP Prefixes.", pdu_type);
	return 0;
}

static int
handle_delta(struct delta const *delta, void *arg)
{
	ck_assert_int_eq(0, send_prefix_pdu(arg, &delta->vrp, delta->flags));
	return 0;
}

int
send_pdus_delta(struct deltas_db *deltas, struct sender_common *common)
{
	struct delta_group *group;

	ARRAYLIST_FOREACH(deltas, group)
		ck_assert_int_eq(0, deltas_foreach(group->serial, group->deltas,
		    handle_delta, common));

	return 0;
}

int
send_end_of_data_pdu(struct sender_common *common, serial_t end_serial)
{
	pr_info("    Server sent End of Data.");
	ck_assert_int_eq(pop_expected_pdu(), PDU_TYPE_END_OF_DATA);
	return 0;
}

int
send_error_report_pdu(int fd, uint8_t version, uint16_t code,
struct pdu_header *err_pdu_header, char const *message)
{
	pr_info("    Server sent Error Report %u: '%s'", code, message);
	ck_assert_int_eq(pop_expected_pdu(), PDU_TYPE_ERROR_REPORT);
	return 0;
}

/* Tests */

/* https://tools.ietf.org/html/rfc6810#section-6.1 */
START_TEST(test_start_or_restart)
{
	struct reset_query_pdu client_pdu;

	pr_info("-- Start or Restart --");

	/* Prepare DB */
	init_db_full();

	/* Init client request */
	init_reset_query(&client_pdu);

	/* Define expected server response */
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX);
	expected_pdu_add(PDU_TYPE_END_OF_DATA);

	/* Run and validate */
	ck_assert_int_eq(0, handle_reset_query_pdu(0, &client_pdu));
	ck_assert_uint_eq(false, has_expected_pdus());

	/* Clean up */
	vrps_destroy();
}
END_TEST

/* https://tools.ietf.org/html/rfc6810#section-6.2 */
START_TEST(test_typical_exchange)
{
	struct serial_query_pdu client_pdu;

	pr_info("-- Typical Exchange --");

	/* Prepare DB */
	init_db_full();

	/* From serial 0: Init client request */
	init_serial_query(&client_pdu, 0);

	/* From serial 0: Define expected server response */
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX);
	expected_pdu_add(PDU_TYPE_END_OF_DATA);

	/* From serial 0: Run and validate */
	ck_assert_int_eq(0, handle_serial_query_pdu(0, &client_pdu));
	ck_assert_uint_eq(false, has_expected_pdus());

	/* From serial 1: Init client request */
	init_serial_query(&client_pdu, 1);

	/* From serial 1: Define expected server response */
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX);
	expected_pdu_add(PDU_TYPE_END_OF_DATA);

	/* From serial 1: Run and validate */
	ck_assert_int_eq(0, handle_serial_query_pdu(0, &client_pdu));
	ck_assert_uint_eq(false, has_expected_pdus());

	/* From serial 2: Init client request */
	init_serial_query(&client_pdu, 2);

	/* From serial 2: Define expected server response */
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE);
	expected_pdu_add(PDU_TYPE_END_OF_DATA);

	/* From serial 2: Run and validate */
	ck_assert_int_eq(0, handle_serial_query_pdu(0, &client_pdu));
	ck_assert_uint_eq(false, has_expected_pdus());

	/* Clean up */
	vrps_destroy();
}
END_TEST

/* https://tools.ietf.org/html/rfc6810#section-6.3 */
START_TEST(test_no_incremental_update_available)
{
	struct serial_query_pdu serial_query;

	pr_info("-- No Incremental Update Available --");

	/* Prepare DB */
	init_db_full();

	/* Init client request */
	init_serial_query(&serial_query, 10000);

	/* Define expected server response */
	expected_pdu_add(PDU_TYPE_CACHE_RESET);

	/* Run and validate */
	ck_assert_int_eq(0, handle_serial_query_pdu(0, &serial_query));
	ck_assert_uint_eq(false, has_expected_pdus());

	/* The Reset Query is already tested in start_or_restart. */

	/* Clean up */
	vrps_destroy();
}
END_TEST

/* https://tools.ietf.org/html/rfc6810#section-6.4 */
START_TEST(test_cache_has_no_data_available)
{
	struct serial_query_pdu serial_query;
	struct reset_query_pdu reset_query;

	pr_info("-- Cache Has No Data Available --");

	/* Prepare DB */
	ck_assert_int_eq(0, vrps_init());

	/* Serial Query: Init client request */
	init_serial_query(&serial_query, 0);

	/* Serial Query: Define expected server response */
	expected_pdu_add(PDU_TYPE_ERROR_REPORT);

	/* Serial Query: Run and validate */
	ck_assert_int_eq(0, handle_serial_query_pdu(0, &serial_query));
	ck_assert_uint_eq(false, has_expected_pdus());

	/* Reset Query: Init client request */
	init_reset_query(&reset_query);

	/* Reset Query: Define expected server response */
	expected_pdu_add(PDU_TYPE_ERROR_REPORT);

	/* Reset Query: Run and validate */
	ck_assert_int_eq(0, handle_reset_query_pdu(0, &reset_query));
	ck_assert_uint_eq(false, has_expected_pdus());

	/* Clean up */
	vrps_destroy();
}
END_TEST

Suite *pdu_suite(void)
{
	Suite *suite;
	TCase *core;

	core = tcase_create("RFC6810-Defined Protocol Sequences");
	tcase_add_test(core, test_start_or_restart);
	tcase_add_test(core, test_typical_exchange);
	tcase_add_test(core, test_no_incremental_update_available);
	tcase_add_test(core, test_cache_has_no_data_available);

	/* TODO (now) add an unhappy path TCase. */

	suite = suite_create("PDU Handler");
	suite_add_tcase(suite, core);
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
