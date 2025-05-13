#include <check.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/queue.h>

#include "alloc.c"
#include "common.c"
#include "mock.c"
#include "types/router_key.c"
#include "types/serial.c"
#include "types/vrp.c"
#include "rtr/pdu_handler.c"
#include "rtr/err_pdu.c"
#include "rtr/db/delta.c"
#include "rtr/db/deltas_array.c"
#include "rtr/db/db_table.c"
#include "rtr/db/rtr_db_mock.c"
#include "rtr/db/vrps.c"

/* Mocks */

MOCK_INT(slurm_apply, 0, struct db_table *base, struct db_slurm **slurm)
MOCK_ABORT_VOID(db_slurm_destroy, struct db_slurm *db)
MOCK_VOID(output_print_data, struct db_table const *db)
__MOCK_ABORT(config_get_local_repository, char const *, "tmp/pdu", void)

/* Mocks end */

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

/*
 * This initializes the database using the test values from
 * db/rtr_db_mock.c.
 */
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
init_reset_query(struct rtr_request *request)
{
	static unsigned char raw[] = { 1, 2, 0, 0, 0, 0, 0, 8 };

	request->fd = 0;
	strcpy(request->client_addr, "192.0.2.1");
	request->pdu.rtr_version = RTR_V1;
	request->pdu.type = PDU_TYPE_RESET_QUERY;
	request->pdu.raw.bytes = raw;
	request->pdu.raw.bytes_len = sizeof(raw);
	request->eos = true;
}

static void
init_serial_query(struct rtr_request *request, uint32_t serial)
{
	static unsigned char raw[] = { 1, 1, 0, 0, 0, 0, 0, 12, 0, 0, 0, 0 };

	request->fd = 0;
	strcpy(request->client_addr, "192.0.2.1");
	request->pdu.rtr_version = RTR_V1;
	request->pdu.type = PDU_TYPE_SERIAL_QUERY;
	request->pdu.obj.sq.session_id = get_current_session_id(RTR_V1);
	request->pdu.obj.sq.serial_number = serial;
	request->pdu.raw.bytes = raw;
	request->pdu.raw.bytes_len = sizeof(raw);
	request->eos = true;
}

/* Mocks */

MOCK_UINT(config_get_deltas_lifetime, 5, void)

int
send_cache_reset_pdu(int fd, uint8_t version)
{
	pr_op_info("    Server sent Cache Reset.");
	ck_assert_int_eq(pop_expected_pdu(), PDU_TYPE_CACHE_RESET);
	return 0;
}

int
send_cache_response_pdu(int fd, uint8_t version)
{
	pr_op_info("    Server sent Cache Response.");
	ck_assert_int_eq(pop_expected_pdu(), PDU_TYPE_CACHE_RESPONSE);
	return 0;
}

static char const *
flags2str(uint8_t flags)
{
	switch (flags) {
	case FLAG_ANNOUNCEMENT:
		return "add";
	case FLAG_WITHDRAWAL:
		return "rm";
	}
	return "unk";
}

int
send_prefix_pdu(int fd, uint8_t version, struct vrp const *vrp, uint8_t flags)
{
	/*
	 * We don't care about order.
	 * If the server is expected to return `M` IPv4 PDUs and `N` IPv6 PDUs,
	 * we'll just check `M + N` contiguous Prefix PDUs.
	 */
	uint8_t pdu_type = pop_expected_pdu();
	pr_op_info("    Server sent Prefix PDU.");

	switch (vrp->addr_fam) {
	case AF_INET:
		printf("%s asn%u IPv4\n", flags2str(flags), vrp->asn);
		break;
	case AF_INET6:
		printf("%s asn%u IPv6\n", flags2str(flags), vrp->asn);
		break;
	default:
		printf("%s asn%u Unknown\n", flags2str(flags), vrp->asn);
		break;
	}

	ck_assert_msg(pdu_type == PDU_TYPE_IPV4_PREFIX
	    || pdu_type == PDU_TYPE_IPV6_PREFIX,
	    "Server sent a prefix. Expected PDU type was %d.", pdu_type);
	return 0;
}

int
send_router_key_pdu(int fd, uint8_t version,
    struct router_key const *router_key, uint8_t flags)
{
	/*
	 * We don't care about order.
	 * If the server is expected to return `M` IPv4 PDUs and `N` IPv6 PDUs,
	 * we'll just check `M + N` contiguous Prefix PDUs.
	 */
	uint8_t pdu_type = pop_expected_pdu();
	pr_op_info("    Server sent Router Key PDU.");
	printf("%s asn%u RK\n", flags2str(flags), router_key->as);
	ck_assert_msg(pdu_type == PDU_TYPE_ROUTER_KEY,
	    "Server sent a Router Key. Expected PDU type was %d.", pdu_type);
	return 0;
}

int
send_end_of_data_pdu(int fd, uint8_t version, serial_t end_serial)
{
	pr_op_info("    Server sent End of Data.");
	ck_assert_int_eq(pop_expected_pdu(), PDU_TYPE_END_OF_DATA);
	return 0;
}

int
send_error_report_pdu(int fd, uint8_t version, uint16_t code,
    struct rtr_buffer const *request, char *message)
{
	pr_op_info("    Server sent Error Report %u: '%s'", code, message);
	ck_assert_int_eq(pop_expected_pdu(), PDU_TYPE_ERROR_REPORT);
	return 0;
}

/* Tests */

/* https://tools.ietf.org/html/rfc8210#section-8.1 */
START_TEST(test_start_or_restart)
{
	struct rtr_request request;

	pr_op_info("-- Start or Restart --");

	/* Init */
	init_db_full();
	init_reset_query(&request);

	/* Define expected server response */
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX);
	expected_pdu_add(PDU_TYPE_ROUTER_KEY);
	expected_pdu_add(PDU_TYPE_END_OF_DATA);

	/* Run and validate */
	handle_reset_query_pdu(&request);
	ck_assert_uint_eq(false, has_expected_pdus());

	/* Clean up */
	vrps_destroy();
}
END_TEST

/* https://tools.ietf.org/html/rfc8210#section-8.2 */
START_TEST(test_typical_exchange)
{
	struct rtr_request request;

	pr_op_info("-- Typical Exchange --");

	/* Init */
	init_db_full();
	init_serial_query(&request, 0);

	/* From serial 0: Define expected server response */
	/* Server doesn't have serial 0. */
	expected_pdu_add(PDU_TYPE_CACHE_RESET);

	/* From serial 0: Run and validate */
	ck_assert_int_eq(0, handle_serial_query_pdu(&request));
	ck_assert_uint_eq(false, has_expected_pdus());

	/* From serial 1: Init client request */
	init_serial_query(&request, 1);

	/* From serial 1: Define expected server response */
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX);
	expected_pdu_add(PDU_TYPE_ROUTER_KEY);
	expected_pdu_add(PDU_TYPE_ROUTER_KEY);
	expected_pdu_add(PDU_TYPE_END_OF_DATA);

	/* From serial 1: Run and validate */
	ck_assert_int_eq(0, handle_serial_query_pdu(&request));
	ck_assert_uint_eq(false, has_expected_pdus());

	/* From serial 2: Init client request */
	init_serial_query(&request, 2);

	/* From serial 2: Define expected server response */
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX);
	expected_pdu_add(PDU_TYPE_ROUTER_KEY);
	expected_pdu_add(PDU_TYPE_END_OF_DATA);

	/* From serial 2: Run and validate */
	ck_assert_int_eq(0, handle_serial_query_pdu(&request));
	ck_assert_uint_eq(false, has_expected_pdus());

	/* From serial 3: Init client request */
	init_serial_query(&request, 3);

	/* From serial 3: Define expected server response */
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE);
	expected_pdu_add(PDU_TYPE_END_OF_DATA);

	/* From serial 3: Run and validate */
	ck_assert_int_eq(0, handle_serial_query_pdu(&request));
	ck_assert_uint_eq(false, has_expected_pdus());

	/* Clean up */
	vrps_destroy();
}
END_TEST

/* https://tools.ietf.org/html/rfc8210#section-8.3 */
START_TEST(test_no_incremental_update_available)
{
	struct rtr_request request;

	pr_op_info("-- No Incremental Update Available --");

	/* Init */
	init_db_full();
	init_serial_query(&request, 10000);

	/* Define expected server response */
	expected_pdu_add(PDU_TYPE_CACHE_RESET);

	/* Run and validate */
	ck_assert_int_eq(0, handle_serial_query_pdu(&request));
	ck_assert_uint_eq(false, has_expected_pdus());

	/* The Reset Query is already tested in start_or_restart. */

	/* Clean up */
	vrps_destroy();
}
END_TEST

/* https://tools.ietf.org/html/rfc8210#section-8.4 */
START_TEST(test_cache_has_no_data_available)
{
	struct rtr_request request;

	pr_op_info("-- Cache Has No Data Available --");

	/* Init */
	ck_assert_int_eq(0, vrps_init());

	/* Serial Query: Init client request */
	init_serial_query(&request, 0);

	/* Serial Query: Define expected server response */
	expected_pdu_add(PDU_TYPE_ERROR_REPORT);

	/* Serial Query: Run and validate */
	ck_assert_int_eq(0, handle_serial_query_pdu(&request));
	ck_assert_uint_eq(false, has_expected_pdus());

	/* Reset Query: Init client request */
	init_reset_query(&request);

	/* Reset Query: Define expected server response */
	expected_pdu_add(PDU_TYPE_ERROR_REPORT);

	/* Reset Query: Run and validate */
	handle_reset_query_pdu(&request);
	ck_assert_uint_eq(false, has_expected_pdus());

	/* Clean up */
	vrps_destroy();
}
END_TEST

START_TEST(test_bad_session_id)
{
	struct rtr_request request;

	pr_op_info("-- Bad Session ID --");

	/* Init */
	init_db_full();
	init_serial_query(&request, 0);
	request.pdu.obj.sq.session_id++;

	/* From serial 0: Define expected server response */
	expected_pdu_add(PDU_TYPE_ERROR_REPORT);

	/* From serial 0: Run and validate */
	ck_assert_int_eq(EINVAL, handle_serial_query_pdu(&request));
	ck_assert_uint_eq(false, has_expected_pdus());

	/* Clean up */
	vrps_destroy();
}
END_TEST

static Suite *create_suite(void)
{
	Suite *suite;
	TCase *core, *error;

	core = tcase_create("RFC8210-Defined Protocol Sequences");
	tcase_add_test(core, test_start_or_restart);
//	tcase_add_test(core, test_typical_exchange);
//	tcase_add_test(core, test_no_incremental_update_available);
//	tcase_add_test(core, test_cache_has_no_data_available);

	error = tcase_create("Unhappy path cases");
//	tcase_add_test(error, test_bad_session_id);

	suite = suite_create("PDU Handler");
	suite_add_tcase(suite, core);
	suite_add_tcase(suite, error);
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
