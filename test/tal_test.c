#include "object/tal.c"

#include <check.h>
#include <errno.h>
#include <stdlib.h>
#include "common.h"

#include "file.c"
#include "impersonator.c"
#include "line_file.c"
#include "log.c"
#include "state.h"
#include "str_token.c"
#include "random.c"
#include "types/uri.c"
#include "crypto/base64.c"
#include "rsync/rsync.c"
#include "thread/thread_pool.c"

/* Impersonate functions that won't be utilized by tests */

int
validation_prepare(struct validation **out, struct tal *tal,
    struct validation_handler *validation_handler)
{
	return 0;
}

int
certificate_traverse(struct rpp *rpp_parent, struct rpki_uri *cert_uri)
{
	return -EINVAL;
}

enum pubkey_state
validation_pubkey_state(struct validation *state)
{
	return PKS_INVALID;
}

void
validation_destroy(struct validation *state)
{
	/* Nothing to destroy */
}

int
process_file_or_dir(char const *location, char const *file_ext, bool empty_err,
    process_file_cb cb, void *arg)
{
	return 0;
}

void
close_thread(pthread_t thread, char const *what)
{
	/* Nothing to close */
}

int
map_uri_to_local(char const *uri, char const *uri_prefix, char const *workspace,
    char **result)
{
	/* These tests focus on global URIs, so set a dummy value */
	*result = strdup("dummy");
	if (*result == NULL)
		return -ENOMEM;
	return 0;
}

void
fnstack_init(void)
{
	/* Empty */
}

void
fnstack_cleanup(void)
{
	/* Empty */
}

void
fnstack_pop(void)
{
	/* Empty */
}

void
fnstack_push(char const *file)
{
	/* Empty */
}

struct validation *
state_retrieve(void)
{
	return NULL;
}

void
db_rrdp_reset_visited_tals(void)
{
	/* Empty */
}

void
db_rrdp_rem_nonvisited_tals(void)
{
	/* Empty */
}

void
panic_on_fail(int error, char const *function_name)
{
	if (error)
		ck_abort_msg("%s() returned errcode %d", function_name, error);
}

void
mutex_lock(pthread_mutex_t *lock)
{
	/* Empty */
}

void
mutex_unlock(pthread_mutex_t *lock)
{
	/* Empty */
}

START_TEST(tal_load_normal)
{
	struct tal *tal;
	unsigned int i;
	/* Got this by feeding the subjectPublicKeyInfo to `base64 -d`. */
	unsigned char decoded[] = {
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

	ck_assert_int_eq(tal_load("tal/lacnic.tal", &tal), 0);

	ck_assert_uint_eq(tal->uris.count, 3);
	ck_assert_str_eq(tal->uris.array[0]->global,
	    "rsync://repository.lacnic.net/rpki/lacnic/rta-lacnic-rpki.cer");
	ck_assert_str_eq(tal->uris.array[1]->global, "https://potato");
	ck_assert_str_eq(tal->uris.array[2]->global, "rsync://potato");

	ck_assert_uint_eq(ARRAY_LEN(decoded), tal->spki_len);
	for (i = 0; i < ARRAY_LEN(decoded); i++)
		ck_assert_uint_eq(tal->spki[i], decoded[i]);

	tal_destroy(tal);
}
END_TEST

START_TEST(tal_order_http_first)
{
	struct tal *tal;

	ck_assert_int_eq(tal_load("tal/lacnic.tal", &tal), 0);

	config_set_http_priority(60);
	config_set_rsync_priority(50);
	ck_assert_int_eq(tal_order_uris(tal), 0);

	ck_assert_str_eq(tal->uris.array[0]->global, "https://potato");
	ck_assert_str_eq(tal->uris.array[1]->global,
	    "rsync://repository.lacnic.net/rpki/lacnic/rta-lacnic-rpki.cer");
	ck_assert_str_eq(tal->uris.array[2]->global, "rsync://potato");

	tal_destroy(tal);
}
END_TEST

START_TEST(tal_order_http_last)
{
	struct tal *tal;

	ck_assert_int_eq(tal_load("tal/lacnic.tal", &tal), 0);

	config_set_http_priority(50);
	config_set_rsync_priority(60);
	ck_assert_int_eq(tal_order_uris(tal), 0);

	ck_assert_str_eq(tal->uris.array[0]->global,
	    "rsync://repository.lacnic.net/rpki/lacnic/rta-lacnic-rpki.cer");
	ck_assert_str_eq(tal->uris.array[1]->global, "rsync://potato");
	ck_assert_str_eq(tal->uris.array[2]->global, "https://potato");

	tal_destroy(tal);
}
END_TEST

Suite *tal_load_suite(void)
{
	Suite *suite;
	TCase *core, *order;

	core = tcase_create("Core");
	tcase_add_test(core, tal_load_normal);

	order = tcase_create("Order");
	tcase_add_test(order, tal_order_http_first);
	tcase_add_test(order, tal_order_http_last);

	suite = suite_create("tal_load()");
	suite_add_tcase(suite, core);
	suite_add_tcase(suite, order);
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
