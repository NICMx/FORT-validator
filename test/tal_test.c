#include "object/tal.c"

#include <check.h>

#include "alloc.c"
#include "common.c"
#include "file.c"
#include "mock.c"
#include "data_structure/path_builder.c"
#include "types/map.c"
#include "crypto/base64.c"

/* Mocks */

MOCK_ABORT_VOID(cache_setup, void)
MOCK(cache_create, struct rpki_cache *, NULL, void)
MOCK_VOID(cache_destroy, struct rpki_cache *cache)
MOCK_ABORT_INT(cache_download, struct rpki_cache *cache,
    struct cache_mapping *map, bool *changed,
    struct cachefile_notification ***notif)
MOCK_ABORT_INT(cache_download_alt, struct rpki_cache *cache,
    struct map_list *maps, enum map_type http_type, enum map_type rsync_type,
    maps_dl_cb cb, void *arg)
MOCK_ABORT_PTR(cache_recover, cache_mapping, struct rpki_cache *cache,
    struct map_list *maps)
MOCK_ABORT_INT(cache_tmpfile, char **filename)
MOCK_ABORT_VOID(cache_teardown, void)
MOCK_ABORT_INT(certificate_traverse, struct rpp *rpp_parent,
    struct cache_mapping *cert_map)
MOCK_ABORT_PTR(db_table_create, db_table, void)
MOCK_VOID(db_table_destroy, struct db_table *table)
MOCK_ABORT_INT(db_table_join, struct db_table *dst, struct db_table *src)
MOCK_ABORT_INT(deferstack_pop, struct cert_stack *stack,
    struct deferred_cert *result)
MOCK_ABORT_VOID(fnstack_cleanup, void)
MOCK_ABORT_VOID(fnstack_init, void)
MOCK_ABORT_VOID(fnstack_push, char const *f)
MOCK_ABORT_INT(handle_roa_v4, uint32_t as, struct ipv4_prefix const *prefix,
    uint8_t max_length, void *arg)
MOCK_ABORT_INT(handle_roa_v6, uint32_t as, struct ipv6_prefix const *prefix,
    uint8_t max_length, void *arg)
MOCK_ABORT_INT(handle_router_key, unsigned char const *ski,
    struct asn_range const *asns, unsigned char const *spk, void *arg)
MOCK_ABORT_VOID(rpp_refput, struct rpp *pp)
MOCK_ABORT_INT(rrdp_update, struct cache_mapping *map)
MOCK(state_retrieve, struct validation *, NULL, void)
MOCK_ABORT_PTR(validation_certstack, cert_stack, struct validation *state)
MOCK_ABORT_VOID(validation_destroy, struct validation *state)
MOCK_ABORT_INT(validation_prepare, struct validation **out, struct tal *tal,
    struct validation_handler *validation_handler)
MOCK_ABORT_ENUM(validation_pubkey_state, pubkey_state, struct validation *state)
MOCK(validation_tal, struct tal *, NULL, struct validation *state)

/* Tests */

static void
check_spki(struct tal *tal)
{
	/* Got this by feeding the subjectPublicKeyInfo to `base64 -d`. */
	static unsigned char spki_raw[] = {
	    0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48,
	    0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01,
	    0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01, 0x00,
	    0xA9, 0x91, 0x33, 0x85, 0x82, 0xB4, 0xF8, 0xFB, 0x43, 0x38, 0xF7,
	    0xEE, 0x6F, 0xF2, 0x91, 0x73, 0x73, 0x1E, 0x5B, 0x1D, 0xE7, 0x79,
	    0x7C, 0x78, 0xFF, 0x06, 0xE7, 0x25, 0x61, 0x9B, 0x34, 0x0B, 0x5B,
	    0x62, 0xA5, 0xE0, 0xDE, 0xE5, 0x39, 0x27, 0x81, 0xC5, 0xCC, 0xF8,
	    0x24, 0xFD, 0x52, 0x29, 0xA6, 0x04, 0x8A, 0x02, 0x19, 0x4E, 0xD0,
	    0x7E, 0xB4, 0x0D, 0x13, 0xF8, 0xF1, 0xBC, 0xBD, 0x82, 0xBE, 0x7F,
	    0xC8, 0x31, 0xEE, 0xD8, 0xA5, 0xE1, 0x3A, 0x69, 0xCC, 0x83, 0x8E,
	    0xAC, 0x62, 0xC5, 0x08, 0xA5, 0xF8, 0x2D, 0x05, 0x2F, 0x7E, 0x56,
	    0xDA, 0xEA, 0x5B, 0x38, 0x89, 0x7D, 0xBF, 0xA9, 0x90, 0x6B, 0x6E,
	    0x39, 0x67, 0x93, 0x9E, 0x3E, 0xB3, 0x06, 0x60, 0x4D, 0x64, 0xA2,
	    0xBE, 0xE4, 0x09, 0x4C, 0x09, 0x6D, 0x56, 0x3E, 0x1A, 0xF2, 0x94,
	    0x87, 0x01, 0xF9, 0x74, 0x99, 0xC7, 0xCB, 0x64, 0xF4, 0x64, 0xBF,
	    0xDD, 0x23, 0x10, 0xF9, 0x87, 0xCC, 0x57, 0x0C, 0x00, 0xC9, 0x88,
	    0xEC, 0x7B, 0x1D, 0x78, 0x53, 0x3B, 0x68, 0xE0, 0x68, 0xCE, 0x34,
	    0x02, 0xC4, 0xE6, 0x88, 0x75, 0x33, 0x7F, 0xA0, 0x95, 0x14, 0x1D,
	    0xB8, 0x3E, 0xAF, 0xCD, 0x2C, 0x0E, 0x0F, 0xE5, 0x9A, 0x84, 0xC6,
	    0xDC, 0xF6, 0xF0, 0x8E, 0x4C, 0x40, 0xFE, 0xD8, 0xC7, 0x0B, 0x1D,
	    0x12, 0xA0, 0x35, 0xA4, 0x1F, 0xD1, 0x82, 0x7D, 0x6B, 0x58, 0xC6,
	    0xF6, 0x82, 0x48, 0xBC, 0x39, 0x0A, 0x5C, 0x4A, 0x9D, 0x7E, 0xA0,
	    0xD1, 0x92, 0xDC, 0x32, 0xA0, 0x3E, 0xF8, 0x71, 0x5E, 0x7B, 0x6D,
	    0x6D, 0xED, 0x04, 0x07, 0xB1, 0x07, 0xB1, 0xA0, 0x94, 0x84, 0xDB,
	    0x22, 0x7C, 0x90, 0x02, 0xC9, 0x9D, 0x9E, 0x0B, 0x5F, 0x83, 0x62,
	    0xD4, 0x32, 0xB7, 0x11, 0x38, 0x71, 0xCF, 0xF3, 0xA4, 0x0F, 0x64,
	    0x83, 0x63, 0x0D, 0x02, 0x03, 0x01, 0x00, 0x01
	};
	unsigned int i;

	ck_assert_uint_eq(ARRAY_LEN(spki_raw), tal->spki_len);
	for (i = 0; i < ARRAY_LEN(spki_raw); i++)
		ck_assert_uint_eq(tal->spki[i], spki_raw[i]);
}

static void
test_1url(char const *file)
{
	struct tal tal;

	ck_assert_int_eq(0, tal_init(&tal, file));

	ck_assert_uint_eq(1, tal.urls.len);
	ck_assert_str_eq("rsync://example.com/rpki/ta.cer", tal.urls.array[0]->url);
	check_spki(&tal);

	tal_cleanup(&tal);
}

START_TEST(test_tal_load_1url)
{
	test_1url("resources/tal/1url-lf.tal");
	test_1url("resources/tal/1url-crlf.tal");
}
END_TEST

static void
test_4urls(char const *file)
{
	struct tal tal;

	ck_assert_int_eq(0, tal_init(&tal, file));

	ck_assert_uint_eq(4, tal.urls.len);
	ck_assert_str_eq("rsync://example.com/rpki/ta.cer", tal.urls.array[0]);
	ck_assert_str_eq("https://example.com/rpki/ta.cer", tal.urls.array[1]);
	ck_assert_str_eq("rsync://www.example.com/potato/ta.cer", tal.urls.array[2]);
	ck_assert_str_eq("https://wx3.example.com/tomato/ta.cer", tal.urls.array[3]);

	check_spki(&tal);

	tal_cleanup(&tal);
}

START_TEST(test_tal_load_4urls)
{
	test_4urls("resources/tal/4urls-lf.tal");
	test_4urls("resources/tal/4urls-crlf.tal");
	test_4urls("resources/tal/4urls-lf-comment.tal");
	test_4urls("resources/tal/4urls-lf-comment-utf8.tal");
}
END_TEST

START_TEST(test_tal_load_error)
{
	struct tal tal;

	ck_assert_int_eq(-EINVAL, tal_init(&tal, "resources/tal/4urls-lf-comment-space-1.tal"));
	ck_assert_int_eq(-EINVAL, tal_init(&tal, "resources/tal/4urls-lf-comment-space-2.tal"));
	ck_assert_int_eq(-EINVAL, tal_init(&tal, "resources/tal/4urls-lf-comment-space-3.tal"));
	ck_assert_int_eq(-EINVAL, tal_init(&tal, "resources/tal/4urls-lf-comment-space-4.tal"));
}
END_TEST

static Suite *tal_load_suite(void)
{
	Suite *suite;
	TCase *core;

	core = tcase_create("Core");
	tcase_add_test(core, test_tal_load_1url);
	tcase_add_test(core, test_tal_load_4urls);
	tcase_add_test(core, test_tal_load_error);

	suite = suite_create("tal_load()");
	suite_add_tcase(suite, core);
	return suite;
}

int main(void)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	suite = tal_load_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
