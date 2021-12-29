#include <check.h>
#include <errno.h>
#include <stdlib.h>

#include "impersonator.c"
#include "log.c"
#include "rrdp/notification.c"
#include "rrdp/types.c"
#include "types/uri.c"
#include "data_structure/path_builder.c"

#define END 0xFFFF

int
relax_ng_parse(char const *path, xml_read_cb cb, void *arg)
{
	pr_crit("Not supposed to be called.");
}

long
file_get_modification_time(char const *luri)
{
	pr_crit("Not supposed to be called.");
}

int
http_get(struct rpki_uri *uri, long ims)
{
	pr_crit("Not supposed to be called.");
}

int
xml_parse_long(xmlTextReaderPtr reader, char const *attr, unsigned long *result)
{
	pr_crit("Not supposed to be called.");
}

int
hash_validate_file(char const *algorithm, struct rpki_uri *uri,
    unsigned char const *expected, size_t expected_len)
{
	pr_crit("Not supposed to be called.");
}

int
create_dir_recursive(char const *path)
{
	pr_crit("Not supposed to be called.");
}

int
base64_decode(BIO *in, unsigned char *out, bool has_nl, size_t out_len,
    size_t *out_written)
{
	pr_crit("Not supposed to be called.");
}

static void
add_serials(struct rrdp_notification_deltas *deltas, ...)
{
	struct rrdp_notification_delta delta;
	va_list vl;

	rrdp_file_metadata_init(&delta.meta);

	va_start(vl, deltas);
	while ((delta.serial = va_arg(vl, unsigned long)) != END)
		ck_assert_int_eq(0, rrdp_notification_deltas_add(deltas, &delta));
	va_end(vl);
}

static void
validate_serials(struct rrdp_notification_deltas *deltas, ...)
{
	unsigned long serial;
	unsigned int i;
	va_list vl;

	va_start(vl, deltas);

	i = 0;
	while ((serial = va_arg(vl, unsigned long)) != END) {
		ck_assert_uint_eq(serial, deltas->array[i].serial);
		i++;
	}

	va_end(vl);
}

START_TEST(test_deltas_head_sort)
{
	struct rrdp_notification_deltas deltas;

	rrdp_notification_deltas_init(&deltas);
	ck_assert_int_eq(0, deltas_head_sort(&deltas, 0));
	ck_assert_int_eq(0, deltas_head_sort(&deltas, 1));
	ck_assert_int_eq(0, deltas_head_sort(&deltas, 2));

	add_serials(&deltas, 0, END);
	ck_assert_int_eq(0, deltas_head_sort(&deltas, 0));
	validate_serials(&deltas, 0, END);

	ck_assert_int_eq(-EINVAL, deltas_head_sort(&deltas, 2));
	ck_assert_int_eq(-EINVAL, deltas_head_sort(&deltas, 1));

	add_serials(&deltas, 1, 2, 3, END);
	ck_assert_int_eq(0, deltas_head_sort(&deltas, 3));
	validate_serials(&deltas, 0, 1, 2, 3, END);

	ck_assert_int_eq(-EINVAL, deltas_head_sort(&deltas, 4));
	ck_assert_int_eq(-EINVAL, deltas_head_sort(&deltas, 2));

	rrdp_notification_deltas_cleanup(&deltas, NULL);
	rrdp_notification_deltas_init(&deltas);

	add_serials(&deltas, 3, 0, 1, 2, END);
	ck_assert_int_eq(0, deltas_head_sort(&deltas, 3));
	validate_serials(&deltas, 0, 1, 2, 3, END);

	rrdp_notification_deltas_cleanup(&deltas, NULL);
	rrdp_notification_deltas_init(&deltas);

	add_serials(&deltas, 4, 3, 2, 1, 0, END);
	ck_assert_int_eq(0, deltas_head_sort(&deltas, 4));
	validate_serials(&deltas, 0, 1, 2, 3, 4, END);

	ck_assert_int_eq(-EINVAL, deltas_head_sort(&deltas, 5));
	ck_assert_int_eq(-EINVAL, deltas_head_sort(&deltas, 3));

	rrdp_notification_deltas_cleanup(&deltas, NULL);
}
END_TEST

Suite *xml_load_suite(void)
{
	Suite *suite;
	TCase *validate;

	validate = tcase_create("Validate");
	tcase_add_test(validate, test_deltas_head_sort);

	suite = suite_create("xml_test()");
	suite_add_tcase(suite, validate);

	return suite;
}

int main(void)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	log_setup(true);

	suite = xml_load_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
