#include <check.h>
#include <stdlib.h>

#include "alloc.c"
#include "common.c"
#include "file.c"
#include "mock.c"
#include "types/address.c"
#include "types/aspa.c"
#include "types/router_key.c"
#include "types/serial.c"
#include "types/vrp.c"
#include "rtr/db/db_table.c"

#define ADDR1 htonl(0xC0000201) /* 192.0.2.1 */
#define ADDR2 htonl(0xC0000202) /* 192.0.2.2 */

#define TOTAL_ROAS 10
#define TOTAL_ASPAS 4
static bool roas_found[TOTAL_ROAS];
static unsigned int total_found;

__MOCK_ABORT(config_get_deltas_lifetime, unsigned int, 0, void)
__MOCK_ABORT(config_get_local_repository, char const *, "tmp/dbt", void)
MOCK_UINT(config_get_max_aspa_providers, 10, void)
MOCK_ABORT_VOID(rtridx_init, struct rtr_index *i)
MOCK_ABORT_INT(rtridx_save, struct rtr_index *i)
MOCK_ABORT_INT(rtridx_load, struct rtr_index *i, bool b)
MOCK_ABORT_INT(rtr_open_file, serial_t serial, char const *basename,
    char const *mode, FILE **result)
__MOCK_ABORT(rtr_filename, char *, NULL, char const *a, char const *b)
__MOCK_ABORT(rtr_filename2, char *, NULL, serial_t serial, char const *b)

static bool
vrp_equals_v4(struct vrp const *vrp, uint8_t as, uint32_t addr,
    uint8_t prefix_len, uint8_t max_prefix_len)
{
	return (AF_INET == vrp->addr_fam)
	    && (as == vrp->asn)
	    && (addr == vrp->prefix.v4.s_addr)
	    && (prefix_len == vrp->prefix_length)
	    && (max_prefix_len == vrp->max_prefix_length);
}

static bool
vrp_equals_v6(struct vrp const *vrp, uint8_t as, uint32_t addr,
    uint8_t prefix_len, uint8_t max_prefix_len)
{
	struct in6_addr tmp;
	in6_addr_init(&tmp, 0x20010DB8u, 0, 0, addr);

	return (AF_INET6 == vrp->addr_fam)
	    && (as == vrp->asn)
	    && addr6_equals(&tmp, &vrp->prefix.v6)
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
foreach_vrp_cb(struct vrp const *vrp, void *arg)
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

START_TEST(test_basic_vrp)
{
	struct ipv4_prefix prefix4;
	struct ipv6_prefix prefix6;
	struct db_table *table;
	array_index i;

	table = db_table_create();
	ck_assert_ptr_ne(NULL, table);

	prefix4.addr.s_addr = ADDR1;
	prefix4.len = 24;
	in6_addr_init(&prefix6.addr, 0x20010DB8u, 0, 0, 1);
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

	/* Change the max prefix length (counts as duplicate) */
	prefix4.len = 24;
	ck_assert_int_eq(0, rtrhandler_handle_roa_v4(table, 10, &prefix4, 30));
	ck_assert_int_eq(0, rtrhandler_handle_roa_v4(table, 10, &prefix4, 30));

	/* IPv6 */
	ck_assert_int_eq(0, rtrhandler_handle_roa_v6(table, 10, &prefix6, 128));
	ck_assert_int_eq(0, rtrhandler_handle_roa_v6(table, 10, &prefix6, 128));

	ck_assert_int_eq(0, rtrhandler_handle_roa_v6(table, 11, &prefix6, 128));
	ck_assert_int_eq(0, rtrhandler_handle_roa_v6(table, 11, &prefix6, 128));

	in6_addr_init(&prefix6.addr, 0x20010DB8u, 0, 0, 2);
	ck_assert_int_eq(0, rtrhandler_handle_roa_v6(table, 10, &prefix6, 128));
	ck_assert_int_eq(0, rtrhandler_handle_roa_v6(table, 10, &prefix6, 128));

	in6_addr_init(&prefix6.addr, 0x20010DB8u, 0, 0, 1);
	prefix6.len = 121;
	ck_assert_int_eq(0, rtrhandler_handle_roa_v6(table, 10, &prefix6, 128));
	ck_assert_int_eq(0, rtrhandler_handle_roa_v6(table, 10, &prefix6, 128));

	prefix6.len = 120;
	ck_assert_int_eq(0, rtrhandler_handle_roa_v6(table, 10, &prefix6, 127));
	ck_assert_int_eq(0, rtrhandler_handle_roa_v6(table, 10, &prefix6, 127));

	/* Check table contents */
	memset(roas_found, 0, sizeof(roas_found));
	total_found = 0;
	ck_assert_int_eq(0, db_table_foreach_roa(table, foreach_vrp_cb, NULL));
	ck_assert_int_eq(TOTAL_ROAS, total_found);
	for (i = 0; i < TOTAL_ROAS; i++)
		ck_assert_int_eq(true, roas_found[i]);

	db_table_destroy(table);
}
END_TEST

static struct aspa *
create_aspa(uint32_t customer, ...)
{
	struct aspa *aspa;
	va_list ap;
	int provider;
	array_index n;

	n = 0;
	va_start(ap, customer);
	while (va_arg(ap, int) != -1)
		n++;
	va_end(ap);

	aspa = pmalloc(sizeof(struct aspa));
	aspa->customer = customer;
	aspa->providers.asids = pcalloc(n, sizeof(uint32_t));
	aspa->providers.count = n;
	aspa->refs = 0;

	n = 0;
	va_start(ap, customer);
	while ((provider = va_arg(ap, int)) != -1)
		aspa->providers.asids[n++] = provider;
	va_end(ap);

	return aspa;
}

static bool
ck_provider(struct aspa const *aspa, uint32_t customer, ...)
{
	va_list ap;
	int provider;
	array_index n;

	if (aspa->customer != customer)
		return false;

	n = 0;
	va_start(ap, customer);
	while (va_arg(ap, int) != -1)
		n++;
	va_end(ap);

	if (aspa->providers.count != n)
		return false;

	n = 0;
	va_start(ap, customer);
	while ((provider = va_arg(ap, int)) != -1)
		if (aspa->providers.asids[n++] != provider)
			return false;
	va_end(ap);

	return true;
}

static int
foreach_aspa_cb(struct aspa const *v, void *arg)
{
	if (ck_provider(v, 1, 100, 200, 300, -1))
		return update_found(0);
	if (ck_provider(v, 2, 100, 200, 300, -1))
		return update_found(1);
	if (ck_provider(v, 3, 500, 600, 700, 800, 900, -1))
		return update_found(2);
	if (ck_provider(v, 4, 500, 600, 700, 800, -1))
		return update_found(3);

	ck_abort_msg("Foreach is looping over unknown ASPA %u/%zu.",
	    v->customer, v->providers.count);
}

START_TEST(test_basic_aspa)
{
	struct db_table *table;
	array_index i;

	table = db_table_create();
	ck_assert_ptr_ne(NULL, table);

	/* Duplicates should be transparently not re-added. */
	ck_assert_int_eq(0, rtrhandler_handle_aspa(table, create_aspa(1, 100, 200, 300, -1)));
	ck_assert_int_eq(0, rtrhandler_handle_aspa(table, create_aspa(1, 100, 200, 300, -1)));

	/* Change the customer slightly */
	ck_assert_int_eq(0, rtrhandler_handle_aspa(table, create_aspa(2, 100, 200, 300, -1)));
	ck_assert_int_eq(0, rtrhandler_handle_aspa(table, create_aspa(2, 100, 200, 300, -1)));

	/* Provider merges */
	ck_assert_int_eq(0, rtrhandler_handle_aspa(table, create_aspa(3, 500, 600, 700, -1)));
	ck_assert_int_eq(0, rtrhandler_handle_aspa(table, create_aspa(3, 800, 900, -1)));

	ck_assert_int_eq(0, rtrhandler_handle_aspa(table, create_aspa(4, 500, 600, 700, -1)));
	ck_assert_int_eq(0, rtrhandler_handle_aspa(table, create_aspa(4, 600, 800, -1)));

	/* Check table contents */
	memset(roas_found, 0, sizeof(roas_found));
	total_found = 0;
	ck_assert_int_eq(0, db_table_foreach_aspa(table, foreach_aspa_cb, NULL));
	ck_assert_int_eq(TOTAL_ASPAS, total_found);
	for (i = 0; i < TOTAL_ASPAS; i++)
		ck_assert_int_eq(true, roas_found[i]);

	db_table_destroy(table);
}
END_TEST

static void
init_providers(struct aspa_providers *provs, ...)
{
	int asn;
	size_t a;
	va_list ap;

	va_start(ap, provs);
	for (a = 0; (asn = va_arg(ap, int)) != 0; a++)
		;
	va_end(ap);

	provs->asids = pcalloc(a, sizeof(uint32_t));
	provs->count = a;

	va_start(ap, provs);
	for (a = 0; (asn = va_arg(ap, int)) != 0; a++)
		provs->asids[a] = asn;
	va_end(ap);
}

static void
ck_merge(struct aspa_providers *a1, struct aspa_providers *a2, ...)
{
	struct aspa_providers res;
	va_list ap;
	size_t a;
	int asn;

	res = merge_providers(a1, a2);

	va_start(ap, a2);
	for (a = 0; (asn = va_arg(ap, int)) != 0; a++)
		ck_assert_uint_eq(asn, res.asids[a]);
	va_end(ap);
	ck_assert_uint_eq(a, res.count);
	free(res.asids);

	res = merge_providers(a2, a1);
	va_start(ap, a2);
	for (a = 0; (asn = va_arg(ap, int)) != 0; a++)
		ck_assert_uint_eq(asn, res.asids[a]);
	va_end(ap);
	ck_assert_uint_eq(a, res.count);
	free(res.asids);
}

START_TEST(test_aspa_merge)
{
	struct aspa_providers a, b;

	init_providers(&a, 1, 2, 3, 0);
	init_providers(&b, 5, 6, 7, 0);
	ck_merge(&a, &b, 1, 2, 3, 5, 6, 7, 0);

	init_providers(&a, 1, 3, 5, 0);
	init_providers(&b, 2, 4, 6, 0);
	ck_merge(&a, &b, 1, 2, 3, 4, 5, 6, 0);

	init_providers(&a, 2, 4, 10, 0);
	init_providers(&b, 6, 8, 12, 0);
	ck_merge(&a, &b, 2, 4, 6, 8, 10, 12, 0);

	init_providers(&a, 1, 2, 3, 4, 0);
	init_providers(&b, 1, 2, 3, 4, 0);
	ck_merge(&a, &b, 1, 2, 3, 4, 0);

	init_providers(&a, 1, 2, 3, 0);
	init_providers(&b, 1, 2, 4, 6, 0);
	ck_merge(&a, &b, 1, 2, 3, 4, 6, 0);

	init_providers(&a, 1, 2, 3, 0);
	init_providers(&b, 1, 2, 3, 4, 5, 0);
	ck_merge(&a, &b, 1, 2, 3, 4, 5, 0);
}
END_TEST

static Suite *pdu_suite(void)
{
	Suite *suite;
	TCase *core;

	core = tcase_create("Core");
	tcase_add_test(core, test_basic_vrp);
	tcase_add_test(core, test_basic_aspa);
	tcase_add_test(core, test_aspa_merge);

	suite = suite_create("DB Table");
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
