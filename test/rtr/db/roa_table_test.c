#include <check.h>
#include <stdlib.h>
#include "thread_var.h"
#include "rtr/db/roa_table.h"

#define ADDR1 htonl(0xC0000201) /* 192.0.2.1 */
#define ADDR2 htonl(0xC0000202) /* 192.0.2.2 */

#define TOTAL_ROAS 10
static bool roas_found[TOTAL_ROAS];
static unsigned int total_found;

static bool
vrp_equals_v4(struct vrp *vrp, uint8_t as, uint32_t addr, uint8_t prefix_len,
    uint8_t max_prefix_len)
{
	return (AF_INET == vrp->addr_fam)
	    && (as == vrp->asn)
	    && (addr == vrp->prefix.v4.s_addr)
	    && (prefix_len == vrp->prefix_length)
	    && (max_prefix_len == vrp->max_prefix_length);
}

static bool
vrp_equals_v6(struct vrp *vrp, uint8_t as, uint32_t addr, uint8_t prefix_len,
    uint8_t max_prefix_len)
{
	return (AF_INET6 == vrp->addr_fam)
	    && (as == vrp->asn)
	    && (htonl(0x20010DB8) == vrp->prefix.v6.s6_addr32[0])
	    && (0 == vrp->prefix.v6.s6_addr32[1])
	    && (0 == vrp->prefix.v6.s6_addr32[2])
	    && (htonl(addr) == vrp->prefix.v6.s6_addr32[3])
	    && (prefix_len == vrp->prefix_length)
	    && (max_prefix_len == vrp->max_prefix_length);
}

static int
update_found(array_index index)
{
	ck_assert_int_eq(false, roas_found[index]);
	roas_found[index] = true;
	total_found++;
	return 0;
}

static int
foreach_cb(struct vrp *vrp, void *arg)
{
	char const *str;

	if (vrp_equals_v4(vrp, 10, ADDR1, 24, 32))
		return update_found(0);
	if (vrp_equals_v4(vrp, 11, ADDR1, 24, 32))
		return update_found(1);
	if (vrp_equals_v4(vrp, 10, ADDR2, 24, 32))
		return update_found(2);
	if (vrp_equals_v4(vrp, 10, ADDR1, 25, 32))
		return update_found(3);
	if (vrp_equals_v4(vrp, 10, ADDR1, 24, 30))
		return update_found(4);

	if (vrp_equals_v6(vrp, 10, 1, 120, 128))
		return update_found(5);
	if (vrp_equals_v6(vrp, 11, 1, 120, 128))
		return update_found(6);
	if (vrp_equals_v6(vrp, 10, 2, 120, 128))
		return update_found(7);
	if (vrp_equals_v6(vrp, 10, 1, 121, 128))
		return update_found(8);
	if (vrp_equals_v6(vrp, 10, 1, 120, 127))
		return update_found(9);

	switch (vrp->addr_fam) {
	case AF_INET:
		str = v4addr2str(&vrp->prefix.v4);
		break;
	case AF_INET6:
		str = v6addr2str(&vrp->prefix.v6);
		break;
	default:
		ck_abort_msg("Unknown address family: %u", vrp->addr_fam);
	}

	ck_abort_msg("Foreach is looping over unknown VRP %u/%s/%u/%u.",
	    vrp->asn, str, vrp->prefix_length, vrp->max_prefix_length);
}

START_TEST(test_basic)
{
	struct ipv4_prefix prefix4;
	struct ipv6_prefix prefix6;
	struct roa_table *table;
	array_index i;

	table = roa_table_create();
	ck_assert_ptr_ne(NULL, table);

	prefix4.addr.s_addr = ADDR1;
	prefix4.len = 24;
	prefix6.addr.s6_addr32[0] = htonl(0x20010DB8);
	prefix6.addr.s6_addr32[1] = 0;
	prefix6.addr.s6_addr32[2] = 0;
	prefix6.addr.s6_addr32[3] = htonl(0x00000001);
	prefix6.len = 120;

	/* Duplicates should be transparently not re-added. */

	ck_assert_int_eq(0, rtrhandler_handle_roa_v4(table, 10, &prefix4, 32));
	ck_assert_int_eq(0, rtrhandler_handle_roa_v4(table, 10, &prefix4, 32));

	/* Change the AS slightly */
	ck_assert_int_eq(0, rtrhandler_handle_roa_v4(table, 11, &prefix4, 32));
	ck_assert_int_eq(0, rtrhandler_handle_roa_v4(table, 11, &prefix4, 32));

	/* Change the prefix slightly */
	prefix4.addr.s_addr = ADDR2;
	ck_assert_int_eq(0, rtrhandler_handle_roa_v4(table, 10, &prefix4, 32));
	ck_assert_int_eq(0, rtrhandler_handle_roa_v4(table, 10, &prefix4, 32));

	prefix4.addr.s_addr = ADDR1;
	prefix4.len = 25;
	ck_assert_int_eq(0, rtrhandler_handle_roa_v4(table, 10, &prefix4, 32));
	ck_assert_int_eq(0, rtrhandler_handle_roa_v4(table, 10, &prefix4, 32));

	/* Change the max prefix length slightly */
	prefix4.len = 24;
	ck_assert_int_eq(0, rtrhandler_handle_roa_v4(table, 10, &prefix4, 30));
	ck_assert_int_eq(0, rtrhandler_handle_roa_v4(table, 10, &prefix4, 30));

	/* IPv6 */
	ck_assert_int_eq(0, rtrhandler_handle_roa_v6(table, 10, &prefix6, 128));
	ck_assert_int_eq(0, rtrhandler_handle_roa_v6(table, 10, &prefix6, 128));

	ck_assert_int_eq(0, rtrhandler_handle_roa_v6(table, 11, &prefix6, 128));
	ck_assert_int_eq(0, rtrhandler_handle_roa_v6(table, 11, &prefix6, 128));

	prefix6.addr.s6_addr32[3] = htonl(0x00000002);
	ck_assert_int_eq(0, rtrhandler_handle_roa_v6(table, 10, &prefix6, 128));
	ck_assert_int_eq(0, rtrhandler_handle_roa_v6(table, 10, &prefix6, 128));

	prefix6.addr.s6_addr32[3] = htonl(0x00000001);
	prefix6.len = 121;
	ck_assert_int_eq(0, rtrhandler_handle_roa_v6(table, 10, &prefix6, 128));
	ck_assert_int_eq(0, rtrhandler_handle_roa_v6(table, 10, &prefix6, 128));

	prefix6.len = 120;
	ck_assert_int_eq(0, rtrhandler_handle_roa_v6(table, 10, &prefix6, 127));
	ck_assert_int_eq(0, rtrhandler_handle_roa_v6(table, 10, &prefix6, 127));

	/* Check table contents */
	memset(roas_found, 0, sizeof(roas_found));
	total_found = 0;
	ck_assert_int_eq(0, roa_table_foreach_roa(table, foreach_cb, NULL));
	ck_assert_int_eq(TOTAL_ROAS, total_found);
	for (i = 0; i < TOTAL_ROAS; i++)
		ck_assert_int_eq(true, roas_found[i]);

	roa_table_put(table);
}
END_TEST

Suite *pdu_suite(void)
{
	Suite *suite;
	TCase *core;

	core = tcase_create("Core");
	tcase_add_test(core, test_basic);

	suite = suite_create("ROA Table");
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
