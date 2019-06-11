#include <check.h>
#include <stdbool.h>
#include <stdlib.h>

#include "crypto/base64.c"
#include "common.c"
#include "file.c"
#include "impersonator.c"
#include "json_parser.c"
#include "log.c"
#include "output_printer.c"
#include "rtr/db/delta.c"
#include "rtr/db/roa_table.c"
#include "rtr/db/rtr_db_impersonator.c"
#include "rtr/db/vrps.c"
#include "slurm/slurm_db.c"
#include "slurm/slurm_loader.c"
#include "slurm/slurm_parser.c"

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
static const bool iteration3_base[] = { 1, 0, 1, 0, };

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

/* Deltas with rules that override each other */
static const bool deltas_0to3_ovrd[] = { 1, 1, 1, 1, 1, 1, 1, 1, };
static const bool deltas_1to3_ovrd[] = { 1, 1, 1, 1, 1, 0, 1, 0, };
static const bool deltas_2to3_ovrd[] = { 0, 1, 0, 1, 1, 0, 1, 0, };
static const bool deltas_3to3_ovrd[] = { 0, 0, 0, 0, 0, 0, 0, 0, };

/* Deltas cleaned up */
static const bool deltas_0to3_clean[] = { 0, 0, 0, 0, 0, 0, 0, 0, };
static const bool deltas_1to3_clean[] = { 0, 1, 0, 1, 0, 0, 0, 0, };
static const bool deltas_2to3_clean[] = { 0, 1, 0, 1, 1, 0, 1, 0, };
static const bool deltas_3to3_clean[] = { 0, 0, 0, 0, 0, 0, 0, 0, };

/* Impersonator functions */

serial_t current_min_serial = 0;

int
clients_get_min_serial(serial_t *result)
{
	*result = current_min_serial;
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
	return -EINVAL;
}

static array_index
get_vrp_index(struct vrp const *vrp)
{
	struct in6_addr tmp;
	array_index family_bit;

	switch (vrp->addr_fam) {
	case AF_INET:
		ck_assert_uint_eq(htonl(0xC0000200), vrp->prefix.v4.s_addr);
		ck_assert_uint_eq(24, vrp->prefix_length);
		ck_assert_uint_eq(32, vrp->max_prefix_length);
		family_bit = 0;
		break;

	case AF_INET6:
		in6_addr_init(&tmp, 0x20010DB8u, 0, 0, 0);
		ck_assert(IN6_ARE_ADDR_EQUAL(&tmp, &vrp->prefix.v6));
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

static int
vrp_add(struct delta const *delta, void *arg)
{
	struct deltas *deltas = arg;
	struct vrp const *vrp;
	struct v4_address v4;
	struct v6_address v6;

	vrp = &delta->vrp;
	switch (vrp->addr_fam) {
	case AF_INET:
		v4.prefix.len = vrp->prefix_length;
		v4.prefix.addr = vrp->prefix.v4;
		v4.max_length = vrp->max_prefix_length;
		deltas_add_roa_v4(deltas, vrp->asn, &v4, delta->flags);
		break;
	case AF_INET6:
		v6.prefix.len = vrp->prefix_length;
		v6.prefix.addr = vrp->prefix.v6;
		v6.max_length = vrp->max_prefix_length;
		deltas_add_roa_v6(deltas, vrp->asn, &v6, delta->flags);
		break;
	default:
		ck_abort_msg("Unknown addr family");
	}
	return 0;
}

static void
filter_deltas(struct deltas_db *db)
{
	struct deltas_db tmp;
	struct delta_group group;
	struct deltas *deltas;

	group.serial = 0;
	ck_assert_int_eq(0, deltas_create(&deltas));
	group.deltas = deltas;
	ck_assert_int_eq(0, vrps_foreach_filtered_delta(db, vrp_add,
	    group.deltas));
	deltas_db_init(&tmp);
	ck_assert_int_eq(0, deltas_db_add(&tmp, &group));

	*db = tmp;
}

static void
check_deltas(serial_t from, serial_t to, bool const *expected_deltas,
    bool filter)
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

	if (filter)
		filter_deltas(&deltas);

	memset(actual_deltas, 0, sizeof(actual_deltas));
	ARRAYLIST_FOREACH(&deltas, group, i)
		ck_assert_int_eq(0, deltas_foreach(group->serial, group->deltas,
		    delta_check, actual_deltas));
	for (i = 0; i < ARRAY_LEN(actual_deltas); i++)
		ck_assert_uint_eq(expected_deltas[i], actual_deltas[i]);
}

static void
check_no_deltas(serial_t from, serial_t to)
{
	serial_t actual_serial;
	struct deltas_db deltas;

	deltas_db_init(&deltas);
	ck_assert_int_eq(-ESRCH, vrps_get_deltas_from(from, &actual_serial,
	    &deltas));
}

static void
create_deltas_0to1(struct deltas_db *deltas, serial_t *serial, bool *changed,
    bool *iterated_entries)
{
	current_min_serial = 0;

	deltas_db_init(deltas);

	ck_assert_int_eq(0, vrps_init());

	/* First validation not yet performed: Tell routers to wait */
	ck_assert_int_eq(-EAGAIN, get_last_serial_number(serial));
	ck_assert_int_eq(-EAGAIN, vrps_foreach_base_roa(vrp_fail,
	    iterated_entries, serial));
	ck_assert_int_eq(-EAGAIN, vrps_get_deltas_from(0, serial, deltas));

	/* First validation: One tree, no deltas */
	ck_assert_int_eq(0, vrps_update(changed));
	check_serial(0);
	check_base(0, iteration0_base);
	check_deltas(0, 0, deltas_0to0, false);

	/* Second validation: One tree, added deltas */
	ck_assert_int_eq(0, vrps_update(changed));
	check_serial(1);
	check_base(1, iteration1_base);
	check_deltas(0, 1, deltas_0to1, false);
	check_deltas(1, 1, deltas_1to1, false);
}

START_TEST(test_basic)
{
	struct deltas_db deltas;
	serial_t serial;
	bool changed;
	bool iterated_entries[8];

	create_deltas_0to1(&deltas, &serial, &changed, iterated_entries);

	/* Third validation: One tree, removed deltas */
	ck_assert_int_eq(0, vrps_update(&changed));
	check_serial(2);
	check_base(2, iteration2_base);
	check_deltas(0, 2, deltas_0to2, false);
	check_deltas(1, 2, deltas_1to2, false);
	check_deltas(2, 2, deltas_2to2, false);

	vrps_destroy();
}
END_TEST

START_TEST(test_delta_forget)
{
	struct deltas_db deltas;
	serial_t serial;
	bool changed;
	bool iterated_entries[8];

	create_deltas_0to1(&deltas, &serial, &changed, iterated_entries);

	/*
	 * Assume that the client(s) already have serial 1 (serial 2 will be
	 * created) so serial 0 isn't needed anymore.
	 */
	current_min_serial = 1;

	/* Third validation: One tree, removed deltas and delta 0 removed */
	ck_assert_int_eq(0, vrps_update(&changed));
	check_serial(2);
	check_base(2, iteration2_base);
	check_no_deltas(0, 2);
	check_deltas(1, 2, deltas_1to2, false);
	check_deltas(2, 2, deltas_2to2, false);

	vrps_destroy();

	/* Return to its initial value */
	current_min_serial = 0;
}
END_TEST

START_TEST(test_delta_ovrd)
{
	struct deltas_db deltas;
	serial_t serial;
	bool changed;
	bool iterated_entries[8];

	create_deltas_0to1(&deltas, &serial, &changed, iterated_entries);

	/* Third validation: One tree, removed deltas */
	ck_assert_int_eq(0, vrps_update(&changed));
	check_serial(2);
	check_base(2, iteration2_base);
	check_deltas(0, 2, deltas_0to2, false);
	check_deltas(1, 2, deltas_1to2, false);
	check_deltas(2, 2, deltas_2to2, false);

	/* Fourth validation with deltas that override each other */
	ck_assert_int_eq(0, vrps_update(&changed));
	check_serial(3);
	check_base(3, iteration3_base);
	check_deltas(0, 3, deltas_0to3_ovrd, false);
	check_deltas(1, 3, deltas_1to3_ovrd, false);
	check_deltas(2, 3, deltas_2to3_ovrd, false);
	check_deltas(3, 3, deltas_3to3_ovrd, false);

	/* Check "cleaned up" deltas */
	check_deltas(0, 3, deltas_0to3_clean, true);
	check_deltas(1, 3, deltas_1to3_clean, true);
	check_deltas(2, 3, deltas_2to3_clean, true);
	check_deltas(3, 3, deltas_3to3_clean, true);

	vrps_destroy();

	/* Return to its initial value */
	current_min_serial = 0;
}
END_TEST

Suite *pdu_suite(void)
{
	Suite *suite;
	TCase *core;

	core = tcase_create("Core");
	tcase_add_test(core, test_basic);
	tcase_add_test(core, test_delta_forget);
	tcase_add_test(core, test_delta_ovrd);

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
