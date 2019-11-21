#include <check.h>
#include <errno.h>
#include <stdlib.h>

#include <libxml/tree.h>
#include "impersonator.c"
#include "log.c"
#include "xml/relax_ng.c"

START_TEST(relax_ng_valid)
{
	char const *url = "xml/notification.xml";
	xmlDoc *doc;

	relax_ng_init();
	ck_assert_int_eq(relax_ng_validate(url, &doc), 0);
	xmlFreeDoc(doc);
	relax_ng_cleanup();
}
END_TEST

Suite *xml_load_suite(void)
{
	Suite *suite;
	TCase *validate;

	validate = tcase_create("Validate");
	tcase_add_test(validate, relax_ng_valid);

	suite = suite_create("xml_test()");
	suite_add_tcase(suite, validate);

	return suite;
}

int main(void)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	suite = xml_load_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
