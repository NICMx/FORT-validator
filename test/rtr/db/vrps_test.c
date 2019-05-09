#include <check.h>
#include <stdbool.h>
#include <stdlib.h>

#include "common.h"
#include "thread_var.h"
#include "validation_handler.h"
#include "rtr/db/vrps.h"

/* -- Expected database descriptors -- */

/*
 * BASE
 * 0: IPv4, ASN 0
 * 1: IPv4, ASN 1
 * 2: IPv6, ASN 0
 * 3: IPv6, ASN 1
 */
static const bool iteration0_base[] = { 1, 0, 1, 0, };
static const bool iteration1_base[] = { 1, 1, 1, 1, };
static const bool iteration2_base[] = { 0, 1, 0, 1, };

/*
 * DELTA
 * 0: Withdrawal, IPv4, ASN 0    4: Announcement, IPv4, ASN 0
 * 1: Withdrawal, IPv4, ASN 1    5: Announcement, IPv4, ASN 1
 * 2: Withdrawal, IPv6, ASN 0    6: Announcement, IPv6, ASN 0
 * 3: Withdrawal, IPv6, ASN 1    7: Announcement, IPv6, ASN 1
 */

static const bool deltas_0to0[] = { 0, 0, 0, 0, 0, 0, 0, 0, };

static const bool deltas_0to1[] = { 0, 0, 0, 0, 0, 1, 0, 1, };
static const bool deltas_1to1[] = { 0, 0, 0, 0, 0, 0, 0, 0, };

static const bool deltas_0to2[] = { 1, 0, 1, 0, 0, 1, 0, 1, };
static const bool deltas_1to2[] = { 1, 0, 1, 0, 0, 0, 0, 0, };
static const bool deltas_2to2[] = { 0, 0, 0, 0, 0, 0, 0, 0, };

/* Impersonator functions */

serial_t
clients_get_min_serial(void)
{
	return 0;
}

/* Test functions */

static int
vrp_fail(struct vrp const *vrp, void *arg)
{
	char const *addr;

	switch (vrp->addr_fam) {
	case AF_INET:
		addr = v4addr2str(&vrp->prefix.v4);
		break;
	case AF_INET6:
		addr = v6addr2str(&vrp->prefix.v6);
		break;
	default:
		addr = "unknown";
	}

	ck_abort_msg("Expected no callbacks, got VRP %u/%s/%u/%u.",
	    vrp->asn, addr, vrp->prefix_length, vrp->max_prefix_length);
}

static array_index
get_vrp_index(struct vrp const *vrp)
{
	array_index family_bit;

	switch (vrp->addr_fam) {
	case AF_INET:
		ck_assert_uint_eq(htonl(0xC0000200), vrp->prefix.v4.s_addr);
		ck_assert_uint_eq(24, vrp->prefix_length);
		ck_assert_uint_eq(32, vrp->max_prefix_length);
		family_bit = 0;
		break;

	case AF_INET6:
		ck_assert_uint_eq(htonl(0x20010DB8), vrp->prefix.v6.s6_addr32[0]);
		ck_assert_uint_eq(0, vrp->prefix.v6.s6_addr32[1]);
		ck_assert_uint_eq(0, vrp->prefix.v6.s6_addr32[2]);
		ck_assert_uint_eq(0, vrp->prefix.v6.s6_addr32[3]);
		ck_assert_uint_eq(96, vrp->prefix_length);
		ck_assert_uint_eq(120, vrp->max_prefix_length);
		family_bit = 1;
		break;

	default:
		ck_abort_msg("VRP has unknown protocol: %u", vrp->addr_fam);
	}

	ck_assert_msg(vrp->asn <= 1, "Unexpected AS number: %u", vrp->asn);

	return (family_bit << 1) | (vrp->asn << 0);
}

static array_index
get_delta_index(struct delta const *delta)
{
	array_index result;

	result = get_vrp_index(&delta->vrp);
	ck_assert_msg(delta->flags <= 1, "Unexpected flags: %u", delta->flags);

	return (delta->flags << 2) | result;
}

static int
vrp_check(struct vrp const *vrp, void *arg)
{
	bool *array = arg;
	array_index index;

	index = get_vrp_index(vrp);
	ck_assert_uint_eq(false, array[index]);
	array[index] = true;

	return 0;
}

static int
delta_check(struct delta const *delta, void *arg)
{
	bool *array = arg;
	array_index index;

	index = get_delta_index(delta);
	ck_assert_uint_eq(false, array[index]);
	array[index] = true;

	return 0;

}

static void
check_serial(serial_t expected_serial)
{
	serial_t actual_serial;
	ck_assert_int_eq(0, get_last_serial_number(&actual_serial));
	ck_assert_uint_eq(expected_serial, actual_serial);
}

static void
check_base(serial_t expected_serial, bool const *expected_base)
{
	serial_t actual_serial;
	bool actual_base[4];
	array_index i;

	memset(actual_base, 0, sizeof(actual_base));
	ck_assert_int_eq(0, vrps_foreach_base_roa(vrp_check, actual_base,
	    &actual_serial));
	ck_assert_uint_eq(expected_serial, actual_serial);
	for (i = 0; i < ARRAY_LEN(actual_base); i++)
		ck_assert_uint_eq(expected_base[i], actual_base[i]);
}

static void
check_deltas(serial_t from, serial_t to, bool const *expected_deltas)
{
	serial_t actual_serial;
	bool actual_deltas[8];
	struct deltas_db deltas;
	struct delta_group *group;
	array_index i;

	deltas_db_init(&deltas);
	ck_assert_int_eq(0, vrps_get_deltas_from(from, &actual_serial,
	    &deltas));
	ck_assert_uint_eq(to, actual_serial);

	memset(actual_deltas, 0, sizeof(actual_deltas));
	ARRAYLIST_FOREACH(&deltas, group)
		ck_assert_int_eq(0, deltas_foreach(group->serial, group->deltas,
		    delta_check, actual_deltas));
	for (i = 0; i < ARRAY_LEN(actual_deltas); i++)
		ck_assert_uint_eq(expected_deltas[i], actual_deltas[i]);
}

START_TEST(test_basic)
{
	struct deltas_db deltas;
	serial_t serial;
	bool changed;
	bool iterated_entries[8];

	deltas_db_init(&deltas);

	ck_assert_int_eq(0, vrps_init());

	/* First validation not yet performed: Tell routers to wait */
	ck_assert_int_eq(-EAGAIN, get_last_serial_number(&serial));
	ck_assert_int_eq(-EAGAIN, vrps_foreach_base_roa(vrp_fail,
	    iterated_entries, &serial));
	ck_assert_int_eq(-EAGAIN, vrps_get_deltas_from(0, &serial, &deltas));

	/* First validation: One tree, no deltas */
	ck_assert_int_eq(0, vrps_update(&changed));
	check_serial(0);
	check_base(0, iteration0_base);
	check_deltas(0, 0, deltas_0to0);

	/* Second validation: One tree, added deltas */
	ck_assert_int_eq(0, vrps_update(&changed));
	check_serial(1);
	check_base(1, iteration1_base);
	check_deltas(0, 1, deltas_0to1);
	check_deltas(1, 1, deltas_1to1);

	/* Third validation: One tree, removed deltas */
	ck_assert_int_eq(0, vrps_update(&changed));
	check_serial(2);
	check_base(2, iteration2_base);
	check_deltas(0, 2, deltas_0to2);
	check_deltas(1, 2, deltas_1to2);
	check_deltas(2, 2, deltas_2to2);

	vrps_destroy();
}
END_TEST

Suite *pdu_suite(void)
{
	Suite *suite;
	TCase *core;

	core = tcase_create("Core");
	tcase_add_test(core, test_basic);

	suite = suite_create("VRP Database");
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
