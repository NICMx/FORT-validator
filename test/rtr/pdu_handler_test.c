#include <check.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/queue.h>

#include "alloc.c"
#include "common.c"
#include "file.c"
#include "mock.c"
#include "rtr/db/db_table.c"
#include "rtr/err_pdu.c"
#include "rtr/meta.c"
#include "rtr/pdu.c"
#include "rtr/pdu_handler.c"
#include "rtr/pdu_stream.c"
#include "types/aspa.c"
#include "types/router_key.c"
#include "types/serial.c"

unsigned int deltas_lifetime = 5;

MOCK(config_get_local_repository, char const *, "tmp", void)
MOCK_UINT(config_get_deltas_lifetime, deltas_lifetime, void)
MOCK_UINT(config_get_max_aspa_providers, 10, void)

struct sent_pdu {
	enum pdu_type type;
	uint32_t as;
	uint8_t flags;
};

static struct sent_pdu expected[24];
static struct sent_pdu actual[24];
static array_index e, a;

static const unsigned char db_imp_ski[] = {
    0x0e, 0xe9, 0x6a, 0x8e, 0x2f, 0xac, 0x50, 0xce, 0x6c, 0x5f,
    0x93, 0x3e, 0xde, 0x6a, 0xa7, 0x80, 0xa6, 0x85, 0x0e, 0x31
};

static const unsigned char db_imp_spk[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xfa, 0xb9, 0x12,
    0x2d, 0x79, 0x4f, 0xa4, 0xbf, 0xe6, 0xf8, 0xbe, 0xc2, 0x7c,
    0x27, 0xca, 0xae, 0xfd, 0x45, 0x1e, 0xb3, 0x39, 0xe4, 0x5b,
    0x08, 0x73, 0xc7, 0xcc, 0x96, 0x78, 0xc7, 0x13, 0xa6, 0x39,
    0x9d, 0x3b, 0x82, 0x9f, 0x75, 0x20, 0x59, 0xf0, 0x95, 0xea,
    0xc6, 0x2e, 0x19, 0x46, 0x73, 0x3d, 0x9d, 0x04, 0xcb, 0xa0,
    0x2f, 0x7b, 0x39, 0x9f, 0x70, 0x42, 0xd4, 0x07, 0xce, 0xde,
    0x04
};

static void
add_v4(struct db_table *tbl, char const *ip, uint8_t plen, uint8_t mlen, uint32_t as)
{
	struct ipv4_prefix pfx = { 0 };
	ck_assert_int_eq(1, inet_pton(AF_INET, ip, &pfx.addr));
	pfx.len = plen;
	ck_assert_int_eq(0, rtrhandler_handle_roa_v4(tbl, as, &pfx, mlen));
}

static void
add_v6(struct db_table *tbl, char const *ip, uint8_t plen, uint8_t mlen, uint32_t as)
{
	struct ipv6_prefix pfx = { 0 };
	ck_assert_int_eq(1, inet_pton(AF_INET6, ip, &pfx.addr));
	pfx.len = plen;
	ck_assert_int_eq(0, rtrhandler_handle_roa_v6(tbl, as, &pfx, mlen));
}

static void
add_rk(struct db_table *tbl, uint32_t as)
{
	ck_assert_int_eq(0, rtrhandler_handle_router_key(tbl, db_imp_ski, as, db_imp_spk));
}

static void
_add_aspa(struct db_table *tbl, uint32_t customer)
{
	struct aspa *aspa;

	aspa = pmalloc(sizeof(struct aspa));
	aspa->customer = customer;
	aspa->providers.asids = pcalloc(3, sizeof(uint32_t));
	aspa->providers.asids[0] = 100;
	aspa->providers.asids[1] = 200;
	aspa->providers.asids[2] = 300;
	aspa->providers.count = 3;
	aspa->refs = 0;

	ck_assert_int_eq(0, rtrhandler_handle_aspa(tbl, aspa));
}

static struct db_table *
mock_table(serial_t serial)
{
	struct db_table *tbl;

	tbl = db_table_create();
	tbl->rtr.session = 0x1234;
	tbl->rtr.serial = serial;

	return tbl;
}

static void
mock_resources(struct db_table *tbl, uint32_t as)
{
	add_v4(tbl, "192.0.2.0", 24, 32, as);
	add_v6(tbl, "200:db8::", 96, 120, as);
	add_rk(tbl, as);
	_add_aspa(tbl, as);
}

static uint16_t
mock_commit(struct db_table *tbl)
{
	uint16_t session;

	db_table_sort(tbl);
	ck_assert_int_eq(0, db_table_cache(tbl));
	session = tbl->rtr.session;
	db_table_destroy(tbl);

	return session;
}

uint16_t
mock_serial1(void)
{
	struct db_table *tbl = mock_table(1);
	mock_resources(tbl, 1);
	return mock_commit(tbl);
}

void
mock_serial2(void)
{
	struct db_table *tbl = mock_table(2);
	mock_resources(tbl, 1);
	mock_resources(tbl, 2);
	mock_commit(tbl);
}

void
mock_serial3(void)
{
	struct db_table *tbl = mock_table(3);
	mock_resources(tbl, 2);
	mock_commit(tbl);
}

void
mock_serial4(void)
{
	struct db_table *tbl = mock_table(4);
	mock_resources(tbl, 1);
	mock_commit(tbl);
}

static int
send_pdu(enum pdu_type type, uint32_t as, uint8_t flags)
{
	ck_assert_uint_lt(a, ARRAY_LEN(actual));

	actual[a].type = type;
	actual[a].as = as;
	actual[a].flags = flags;

	a++;
	return 0;
}

int
send_serial_notify_pdu(int fd, uint8_t ver, struct rtr_metadata *meta)
{
	return send_pdu(PDU_TYPE_SERIAL_NOTIFY, 0, 0);
}

int
send_cache_reset_pdu(int fd, uint8_t ver)
{
	return send_pdu(PDU_TYPE_CACHE_RESET, 0, 0);
}

int
send_cache_response_pdu(int fd, uint8_t ver, uint16_t session)
{
	return send_pdu(PDU_TYPE_CACHE_RESPONSE, 0, 0);
}

int
send_prefix_pdu(int fd, uint8_t ver, struct vrp const *vrp, uint8_t flags)
{
	switch (vrp->addr_fam) {
	case AF_INET:
		return send_pdu(PDU_TYPE_IPV4_PREFIX, vrp->asn, flags);
	case AF_INET6:
		return send_pdu(PDU_TYPE_IPV6_PREFIX, vrp->asn, flags);
	}
	ck_abort();
}

int
send_router_key_pdu(int fd, uint8_t ver, struct router_key const *rk,
    uint8_t flags)
{
	return send_pdu(PDU_TYPE_ROUTER_KEY, rk->as, flags);
}

int
send_aspa_announce_pdu(int fd, uint8_t ver, struct aspa const *aspa)
{
	return send_pdu(PDU_TYPE_ASPA, aspa->customer, FLAG_ANNOUNCEMENT);
}

int
send_aspa_withdraw_pdu(int fd, uint8_t ver, uint32_t customer)
{
	return send_pdu(PDU_TYPE_ASPA, customer, FLAG_WITHDRAWAL);
}

int
send_end_of_data_pdu(int fd, uint8_t ver, uint16_t session, serial_t serial)
{
	return send_pdu(PDU_TYPE_END_OF_DATA, 0, 0);
}

int
send_error_report_pdu(int fd, uint8_t version, uint16_t code,
    struct rtr_buffer const *request, char *message)
{
	return send_pdu(PDU_TYPE_ERROR_REPORT, 0, 0);
}

static void
check_response(void)
{
	array_index i;

	pr_op_debug("Expected:");
	for (i = 0; i < e; i++)
		pr_op_debug("- %s %u %u", pdutype2str(expected[i].type),
		    expected[i].as, expected[i].flags);
	pr_op_debug("Actual:");
	for (i = 0; i < a; i++)
		pr_op_debug("- %s %u %u", pdutype2str(actual[i].type),
		    actual[i].as, actual[i].flags);

	ck_assert_uint_eq(e, a);
	for (i = 0; i < e; i++) {
		ck_assert_int_eq(expected[i].type, actual[i].type);
		ck_assert_int_eq(expected[i].as, actual[i].as);
		ck_assert_int_eq(expected[i].flags, actual[i].flags);
	}
}

static void
rcv_reset_query(void)
{
	struct pdu_stream stream = { 0 };
	struct rtr_request req = { 0 };
	unsigned char raw[8] = { 0 };

	ck_assert_int_eq(0, pthread_mutex_init(&stream.session_lock, NULL));
	stream.session_set = false;

	req.fd = -1;
	req.stream = &stream;
	req.pdu.rtr_version = RTR_V2;
	req.pdu.type = PDU_TYPE_RESET_QUERY;

	req.pdu.raw.bytes = raw;
	req.pdu.raw.bytes_len = 8;
	raw[0] = RTR_V2;
	raw[1] = PDU_TYPE_RESET_QUERY;
	raw[7] = 8;

	a = 0;
	ck_assert_int_eq(0, handle_reset_query_pdu(&req));
	check_response();
}

static void
rcv_serial_query(uint16_t session, serial_t serial)
{
	struct pdu_stream stream = { 0 };
	struct rtr_request req = { 0 };
	unsigned char raw[12] = { 0 };

	ck_assert_int_eq(0, pthread_mutex_init(&stream.session_lock, NULL));
	stream.session_set = true;
	stream.session = session;

	req.fd = -1;
	req.pdu.rtr_version = RTR_V2;
	req.stream = &stream;
	req.pdu.type = PDU_TYPE_SERIAL_QUERY;
	req.pdu.obj.sq.session_id = session;
	req.pdu.obj.sq.serial_number = serial;

	req.pdu.raw.bytes = raw;
	req.pdu.raw.bytes_len = 12;
	raw[0] = RTR_V2;
	raw[1] = PDU_TYPE_SERIAL_QUERY;
	raw[2] = session >> 8;
	raw[3] = session;
	raw[7] = 12;
	raw[8] = serial >> 24;
	raw[9] = serial >> 16;
	raw[10] = serial >> 8;
	raw[11] = serial;

	a = 0;
	ck_assert_int_eq(0, handle_serial_query_pdu(&req));
	check_response();

	pthread_mutex_destroy(&stream.session_lock);
}

static void
expected_pdu_add(enum pdu_type type, uint32_t as, uint8_t flags)
{
	expected[e].type = type;
	expected[e].as = as;
	expected[e].flags = flags;
	e++;
}

/* https://datatracker.ietf.org/doc/html/rfc8210#section-8.1 */
/* https://datatracker.ietf.org/doc/html/rfc8210#section-8.2 */
START_TEST(test_natural_flows)
{
	uint16_t session;

	pr_op_info("-- Natural Flows --");

	deltas_lifetime = 5;
	if (file_exists("tmp/rtr") == 0)
		ck_assert_int_eq(0, file_rm_rf("tmp/rtr"));

	/* First cycle not yet performed: Tell routers to wait */
	e = 0;
	expected_pdu_add(PDU_TYPE_ERROR_REPORT, 0, 0);
	rcv_reset_query();
	rcv_serial_query(0x1234, 0);

	/* First cycle: One tree, no deltas */
	session = mock_serial1();

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE, 0, 0);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ROUTER_KEY, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ASPA, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_END_OF_DATA, 0, 0);
	rcv_reset_query();

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE, 0, 0);
	expected_pdu_add(PDU_TYPE_END_OF_DATA, 0, 0);
	rcv_serial_query(session, 1);

	/* Second cycle: One tree, added deltas */
	mock_serial2();

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE, 0, 0);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ROUTER_KEY, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ROUTER_KEY, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ASPA, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ASPA, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_END_OF_DATA, 0, 0);
	rcv_reset_query();

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE, 0, 0);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ROUTER_KEY, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ASPA, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_END_OF_DATA, 0, 0);
	rcv_serial_query(session, 1);

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE, 0, 0);
	expected_pdu_add(PDU_TYPE_END_OF_DATA, 0, 0);
	rcv_serial_query(session, 2);

	/* Third cycle: One tree, removed deltas */
	mock_serial3();

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE, 0, 0);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ROUTER_KEY, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ASPA, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_END_OF_DATA, 0, 0);
	rcv_reset_query();

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE, 0, 0);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX, 1, FLAG_WITHDRAWAL);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX, 1, FLAG_WITHDRAWAL);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ROUTER_KEY, 1, FLAG_WITHDRAWAL);
	expected_pdu_add(PDU_TYPE_ROUTER_KEY, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ASPA, 1, FLAG_WITHDRAWAL);
	expected_pdu_add(PDU_TYPE_ASPA, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_END_OF_DATA, 0, 0);
	rcv_serial_query(session, 1);

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE, 0, 0);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX, 1, FLAG_WITHDRAWAL);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX, 1, FLAG_WITHDRAWAL);
	expected_pdu_add(PDU_TYPE_ROUTER_KEY, 1, FLAG_WITHDRAWAL);
	expected_pdu_add(PDU_TYPE_ASPA, 1, FLAG_WITHDRAWAL);
	expected_pdu_add(PDU_TYPE_END_OF_DATA, 0, 0);
	rcv_serial_query(session, 2);

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE, 0, 0);
	expected_pdu_add(PDU_TYPE_END_OF_DATA, 0, 0);
	rcv_serial_query(session, 3);

	/* Fourth cycle: Back to serial 1 data */
	mock_serial4();

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE, 0, 0);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ROUTER_KEY, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ASPA, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_END_OF_DATA, 0, 0);
	rcv_reset_query();

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE, 0, 0);
	expected_pdu_add(PDU_TYPE_END_OF_DATA, 0, 0);
	rcv_serial_query(session, 1);

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE, 0, 0);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX, 2, FLAG_WITHDRAWAL);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX, 2, FLAG_WITHDRAWAL);
	expected_pdu_add(PDU_TYPE_ROUTER_KEY, 2, FLAG_WITHDRAWAL);
	expected_pdu_add(PDU_TYPE_ASPA, 2, FLAG_WITHDRAWAL);
	expected_pdu_add(PDU_TYPE_END_OF_DATA, 0, 0);
	rcv_serial_query(session, 2);

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE, 0, 0);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX, 2, FLAG_WITHDRAWAL);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX, 2, FLAG_WITHDRAWAL);
	expected_pdu_add(PDU_TYPE_ROUTER_KEY, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ROUTER_KEY, 2, FLAG_WITHDRAWAL);
	expected_pdu_add(PDU_TYPE_ASPA, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ASPA, 2, FLAG_WITHDRAWAL);
	expected_pdu_add(PDU_TYPE_END_OF_DATA, 0, 0);
	rcv_serial_query(session, 3);

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE, 0, 0);
	expected_pdu_add(PDU_TYPE_END_OF_DATA, 0, 0);
	rcv_serial_query(session, 4);
}
END_TEST

START_TEST(test_delta_forget)
{
	uint16_t session;

	pr_op_info("-- Delta Forgetting -- ");

	deltas_lifetime = 1;
	if (file_exists("tmp/rtr") == 0)
		ck_assert_int_eq(0, file_rm_rf("tmp/rtr"));

	/* First cycle not yet performed: Tell routers to wait */
	e = 0;
	expected_pdu_add(PDU_TYPE_ERROR_REPORT, 0, 0);
	rcv_reset_query();
	rcv_serial_query(0x1234, 0);

	/* First cycle: One tree, no deltas */
	session = mock_serial1();

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE, 0, 0);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ROUTER_KEY, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ASPA, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_END_OF_DATA, 0, 0);
	rcv_reset_query();

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE, 0, 0);
	expected_pdu_add(PDU_TYPE_END_OF_DATA, 0, 0);
	rcv_serial_query(session, 1);

	/* Second cycle: One tree, added deltas */
	mock_serial2();

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE, 0, 0);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ROUTER_KEY, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ROUTER_KEY, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ASPA, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ASPA, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_END_OF_DATA, 0, 0);
	rcv_reset_query();

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE, 0, 0);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ROUTER_KEY, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ASPA, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_END_OF_DATA, 0, 0);
	rcv_serial_query(session, 1);

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE, 0, 0);
	expected_pdu_add(PDU_TYPE_END_OF_DATA, 0, 0);
	rcv_serial_query(session, 2);

	/* Third cycle: One tree, removed deltas */
	mock_serial3();

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE, 0, 0);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ROUTER_KEY, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ASPA, 2, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_END_OF_DATA, 0, 0);
	rcv_reset_query();

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESET, 0, 0);
	rcv_serial_query(session, 1);

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE, 0, 0);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX, 1, FLAG_WITHDRAWAL);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX, 1, FLAG_WITHDRAWAL);
	expected_pdu_add(PDU_TYPE_ROUTER_KEY, 1, FLAG_WITHDRAWAL);
	expected_pdu_add(PDU_TYPE_ASPA, 1, FLAG_WITHDRAWAL);
	expected_pdu_add(PDU_TYPE_END_OF_DATA, 0, 0);
	rcv_serial_query(session, 2);

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE, 0, 0);
	expected_pdu_add(PDU_TYPE_END_OF_DATA, 0, 0);
	rcv_serial_query(session, 3);

	/* Fourth cycle: Back to serial 1 data */
	mock_serial4();

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE, 0, 0);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ROUTER_KEY, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ASPA, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_END_OF_DATA, 0, 0);
	rcv_reset_query();

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESET, 0, 0);
	rcv_serial_query(session, 1);

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESET, 0, 0);
	rcv_serial_query(session, 2);

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE, 0, 0);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX, 2, FLAG_WITHDRAWAL);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX, 2, FLAG_WITHDRAWAL);
	expected_pdu_add(PDU_TYPE_ROUTER_KEY, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ROUTER_KEY, 2, FLAG_WITHDRAWAL);
	expected_pdu_add(PDU_TYPE_ASPA, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ASPA, 2, FLAG_WITHDRAWAL);
	expected_pdu_add(PDU_TYPE_END_OF_DATA, 0, 0);
	rcv_serial_query(session, 3);

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE, 0, 0);
	expected_pdu_add(PDU_TYPE_END_OF_DATA, 0, 0);
	rcv_serial_query(session, 4);
}
END_TEST

/* https://tools.ietf.org/html/rfc8210#section-8.3 */
START_TEST(test_no_incremental_update_available)
{
	uint16_t session;

	pr_op_info("-- No Incremental Update Available --");

	deltas_lifetime = 5;
	if (file_exists("tmp/rtr") == 0)
		ck_assert_int_eq(0, file_rm_rf("tmp/rtr"));
	session = mock_serial1();
	mock_serial2();
	mock_serial3();
	mock_serial4();

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESET, 0, 0);
	rcv_serial_query(session, 10000);

	e = 0;
	expected_pdu_add(PDU_TYPE_CACHE_RESPONSE, 0, 0);
	expected_pdu_add(PDU_TYPE_IPV4_PREFIX, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_IPV6_PREFIX, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ROUTER_KEY, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_ASPA, 1, FLAG_ANNOUNCEMENT);
	expected_pdu_add(PDU_TYPE_END_OF_DATA, 0, 0);
	rcv_reset_query();
}
END_TEST

/* https://tools.ietf.org/html/rfc8210#section-8.4 */
START_TEST(test_cache_has_no_data_available)
{
	pr_op_info("-- Cache Has No Data Available --");

	deltas_lifetime = 5;
	if (file_exists("tmp/rtr") == 0)
		ck_assert_int_eq(0, file_rm_rf("tmp/rtr"));

	e = 0;
	expected_pdu_add(PDU_TYPE_ERROR_REPORT, 0, 0);
	rcv_serial_query(0x1234, 0);
	rcv_reset_query();
}
END_TEST

static Suite *
pdu_suite(void)
{
	Suite *suite;
	TCase *core;

	core = tcase_create("RTR flows");
	tcase_add_test(core, test_natural_flows);
	tcase_add_test(core, test_delta_forget);
	tcase_add_test(core, test_no_incremental_update_available);
	tcase_add_test(core, test_cache_has_no_data_available);

	suite = suite_create("PDU Handler");
	suite_add_tcase(suite, core);
	return suite;
}

int
main(void)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;
	int error;

	error = mkdir_f("tmp");
	if (error)
		return error;

	suite = pdu_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
