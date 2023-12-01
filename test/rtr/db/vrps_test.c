#include <check.h>
#include <stdbool.h>
#include <stdlib.h>

#include "crypto/base64.c"
#include "algorithm.c"
#include "alloc.c"
#include "common.c"
#include "file.c"
#include "json_util.c"
#include "mock.c"
#include "output_printer.c"
#include "types/delta.c"
#include "types/router_key.c"
#include "types/serial.c"
#include "types/vrp.c"
#include "rtr/db/delta.c"
#include "rtr/db/deltas_array.c"
#include "rtr/db/db_table.c"
#include "rtr/db/rtr_db_mock.c"
#include "rtr/db/vrps.c"
#include "slurm/db_slurm.c"
#include "slurm/slurm_loader.c"
#include "slurm/slurm_parser.c"
#include "thread/thread_pool.c"

/* -- Expected database descriptors -- */

/*
 * BASE
 * 0: IPv4, ASN 0
 * 1: IPv4, ASN 1
 * 2: IPv6, ASN 0
 * 3: IPv6, ASN 1
 * 4: Router key, ASN 0
 * 5: Router key, ASN 1
 */
static const bool iteration1_base[] = { 1, 0, 1, 0, 1, 0, };
static const bool iteration2_base[] = { 1, 1, 1, 1, 1, 1, };
static const bool iteration3_base[] = { 0, 1, 0, 1, 0, 1, };
static const bool iteration4_base[] = { 1, 0, 1, 0, 1, 0, };

/*
 * DELTA
 * 0: Withdrawal, IPv4, ASN 0    6: Announcement, IPv4, ASN 0
 * 1: Withdrawal, IPv4, ASN 1    7: Announcement, IPv4, ASN 1
 * 2: Withdrawal, IPv6, ASN 0    8: Announcement, IPv6, ASN 0
 * 3: Withdrawal, IPv6, ASN 1    9: Announcement, IPv6, ASN 1
 * 4: Withdrawal, RK,   ASN 0   10: Announcement, RK,   ASN 0
 * 5: Withdrawal, RK,   ASN 1   11: Announcement, RK,   ASN 1
 */

static const bool deltas_1to1[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };

static const bool deltas_1to2[] = { 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, };
static const bool deltas_2to2[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };

static const bool deltas_1to3[] = { 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, };
static const bool deltas_2to3[] = { 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, };
static const bool deltas_3to3[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };

static const bool deltas_1to4[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };
static const bool deltas_2to4[] = { 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, };
static const bool deltas_3to4[] = { 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, };
static const bool deltas_4to4[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };

/* Mocks */

static unsigned int deltas_lifetime = 5;

MOCK_UINT(config_get_deltas_lifetime, deltas_lifetime, void)
MOCK_ABORT_ENUM(config_get_output_format, output_format, void)
MOCK_ABORT_INT(hash_local_file, char const *uri, unsigned char *result,
    unsigned int *result_len)

/* Test functions */

static char const *
vrpaddr2str(struct vrp const *vrp)
{
	switch (vrp->addr_fam) {
	case AF_INET:
		return v4addr2str(&vrp->prefix.v4);
	case AF_INET6:
		return v6addr2str(&vrp->prefix.v6);
	}

	return "unknown";
}

static int
vrp_fail(struct vrp const *vrp, void *arg)
{
	ck_abort_msg("Expected no callbacks, got VRP %u/%s/%u/%u.",
	    vrp->asn, vrpaddr2str(vrp), vrp->prefix_length,
	    vrp->max_prefix_length);
	return -EINVAL;
}

static int
rk_fail(struct router_key const *key, void *arg)
{
	ck_abort_msg("Expected no callbacks, got RK %u.", key->as);
	return -EINVAL;
}

static int
dvrp_fail(struct delta_vrp const *delta, void *arg)
{
	ck_abort_msg("Expected no callbacks, got Delta VRP %u/%s/%u/%u/%u.",
	    delta->vrp.asn, vrpaddr2str(&delta->vrp), delta->vrp.prefix_length,
	    delta->vrp.max_prefix_length, delta->flags);
	return -EINVAL;
}

static int
drk_fail(struct delta_router_key const *delta, void *arg)
{
	ck_abort_msg("Expected no callbacks, got Delta RK %u/%u.",
	    delta->router_key.as, delta->flags);
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
		ck_assert(addr6_equals(&tmp, &vrp->prefix.v6));
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
get_rk_index(struct router_key const *rk)
{
	array_index i;

	for (i = 0; i < RK_SKI_LEN; i++)
		ck_assert_uint_eq(rk->ski[i], db_imp_ski[i]);

	ck_assert_msg(rk->as <= 1, "Unexpected AS number: %u", rk->as);

	for (i = 0; i < RK_SPKI_LEN; i++)
		ck_assert_uint_eq(rk->spk[i], db_imp_spk[i]);

	return rk->as + 4;
}

static array_index
get_delta_vrp_index(struct delta_vrp const *delta)
{
	array_index result;

	result = get_vrp_index(&delta->vrp);
	ck_assert_msg(delta->flags <= 1, "VRP Unexpected flags: %u",
	    delta->flags);

	return result + (delta->flags ? 6 : 0);
}

static array_index
get_delta_rk_index(struct delta_router_key const *delta)
{
	array_index result;

	result = get_rk_index(&delta->router_key);
	ck_assert_msg(delta->flags <= 1, "RK Unexpected flags: %u",
	    delta->flags);

	return result + (delta->flags ? 6 : 0);
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
rk_check(struct router_key const *rk, void *arg)
{
	bool *array = arg;
	array_index index;

	index = get_rk_index(rk);
	ck_assert_uint_eq(false, array[index]);
	array[index] = true;

	return 0;
}

static int
delta_vrp_check(struct delta_vrp const *delta, void *arg)
{
	bool *array = arg;
	array_index index;

	index = get_delta_vrp_index(delta);
	ck_assert_uint_eq(false, array[index]);
	array[index] = true;

	return 0;
}

static int
delta_rk_check(struct delta_router_key const *delta, void *arg)
{
	bool *array = arg;
	array_index index;

	index = get_delta_rk_index(delta);
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
	bool actual_base[6];
	array_index i;

	memset(actual_base, 0, sizeof(actual_base));
	ck_assert_int_eq(0, get_last_serial_number(&actual_serial));
	ck_assert_int_eq(0, vrps_foreach_base(vrp_check, rk_check,
	    actual_base));
	ck_assert_uint_eq(expected_serial, actual_serial);
	for (i = 0; i < ARRAY_LEN(actual_base); i++)
		ck_assert_uint_eq(expected_base[i], actual_base[i]);
}

static int
vrp_add(struct delta_vrp const *delta, void *arg)
{
	return deltas_add_roa(arg, &delta->vrp, delta->flags, 'a', 0, 0);
}

static int
rk_add(struct delta_router_key const *delta, void *arg)
{
	return deltas_add_router_key(arg, &delta->router_key, delta->flags);
}

static void
check_deltas(serial_t from, serial_t to, bool const *expected_deltas)
{
	struct deltas *deltas;
	serial_t actual_serial;
	bool actual_deltas[12];
	array_index i;

	deltas = deltas_create();
	ck_assert_ptr_nonnull(deltas);

	ck_assert_int_eq(0, vrps_foreach_delta_since(from, &actual_serial,
	    vrp_add, rk_add, deltas));
	ck_assert_uint_eq(to, actual_serial);

	memset(actual_deltas, 0, sizeof(actual_deltas));
	ck_assert_int_eq(0, deltas_foreach(deltas, delta_vrp_check,
	    delta_rk_check, actual_deltas));
	for (i = 0; i < ARRAY_LEN(actual_deltas); i++)
		ck_assert_uint_eq(expected_deltas[i], actual_deltas[i]);
}

static void
check_no_deltas(serial_t from)
{
	serial_t actual_to;
	ck_assert_int_eq(-ESRCH, vrps_foreach_delta_since(from, &actual_to,
	    dvrp_fail, drk_fail, NULL));
}

static void
create_deltas_1to2(void)
{
	serial_t serial;
	bool changed;
	bool iterated_entries[12];

	ck_assert_int_eq(0, vrps_init());

	/* First validation not yet performed: Tell routers to wait */
	ck_assert_int_eq(-EAGAIN, get_last_serial_number(&serial));
	ck_assert_int_eq(-EAGAIN, vrps_foreach_base(vrp_fail, rk_fail,
	    iterated_entries));
	ck_assert_int_eq(-EAGAIN, vrps_foreach_delta_since(0, &serial,
	    dvrp_fail, drk_fail, NULL));

	/* First validation: One tree, no deltas */
	ck_assert_int_eq(0, vrps_update(&changed));
	ck_assert(changed);
	check_serial(1);
	check_base(1, iteration1_base);
	check_deltas(1, 1, deltas_1to1);

	/* Second validation: One tree, added deltas */
	ck_assert_int_eq(0, vrps_update(&changed));

	ck_assert(changed);
	check_serial(2);
	check_base(2, iteration2_base);
	check_deltas(1, 2, deltas_1to2);
	check_deltas(2, 2, deltas_2to2);
}

START_TEST(test_basic)
{
	bool changed;

	deltas_lifetime = 5;

	create_deltas_1to2();

	/* Third validation: One tree, removed deltas */
	ck_assert_int_eq(0, vrps_update(&changed));
	ck_assert(changed);
	check_serial(3);
	check_base(3, iteration3_base);
	check_deltas(1, 3, deltas_1to3);
	check_deltas(2, 3, deltas_2to3);
	check_deltas(3, 3, deltas_3to3);

	vrps_destroy();
}
END_TEST

START_TEST(test_delta_forget)
{
	bool changed;

	deltas_lifetime = 1;

	create_deltas_1to2();

	/* Third validation: One tree, removed deltas and delta 1 removed */
	ck_assert_int_eq(0, vrps_update(&changed));
	ck_assert(changed);
	check_serial(3);
	check_base(3, iteration3_base);
	check_no_deltas(1);
	check_deltas(2, 3, deltas_2to3);
	check_deltas(3, 3, deltas_3to3);

	vrps_destroy();
}
END_TEST

START_TEST(test_delta_ovrd)
{
	bool changed;

	deltas_lifetime = 3;

	create_deltas_1to2();

	/* Third validation: One tree, removed deltas */
	ck_assert_int_eq(0, vrps_update(&changed));
	ck_assert(changed);
	check_serial(3);
	check_base(3, iteration3_base);
	check_deltas(1, 3, deltas_1to3);
	check_deltas(2, 3, deltas_2to3);
	check_deltas(3, 3, deltas_3to3);

	/* Fourth validation with deltas that override each other */
	ck_assert_int_eq(0, vrps_update(&changed));
	ck_assert(changed);
	check_serial(4);
	check_base(4, iteration4_base);
	check_deltas(1, 4, deltas_1to4);
	check_deltas(2, 4, deltas_2to4);
	check_deltas(3, 4, deltas_3to4);
	check_deltas(4, 4, deltas_4to4);

	vrps_destroy();
}
END_TEST

static Suite *pdu_suite(void)
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
