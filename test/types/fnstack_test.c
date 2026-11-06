#include <check.h>
#include <errno.h>
#include <stdlib.h>

#include "alloc.c"
#include "types/fnstack.c"

int pr_err(char const *format, ...) { return EINVAL; }
int pr_crit(char const *format, ...) { return EINVAL; }
void enomem_panic(void) { ck_abort_msg("Out of memory."); }

START_TEST(reuse)
{
	fnstack_init();

	ck_assert_ptr_eq(NULL, fnstack_peek());
	fnstack_push("one");
	ck_assert_str_eq("one", fnstack_peek());
	fnstack_pop();
	ck_assert_ptr_eq(NULL, fnstack_peek());

	fnstack_push("a");
	ck_assert_str_eq("a", fnstack_peek());
	fnstack_push("b");
	ck_assert_str_eq("b", fnstack_peek());
	fnstack_pop();
	ck_assert_str_eq("a", fnstack_peek());
	fnstack_push("c");
	ck_assert_str_eq("c", fnstack_peek());
	fnstack_pop();
	ck_assert_str_eq("a", fnstack_peek());
	fnstack_pop();
	ck_assert_ptr_eq(NULL, fnstack_peek());
}
END_TEST

START_TEST(overflow)
{
	fnstack_init();

	ck_assert_ptr_eq(NULL, fnstack_peek());

	fnstack_push("one");
	ck_assert_str_eq("one", fnstack_peek());
	fnstack_push("two");
	ck_assert_str_eq("two", fnstack_peek());
	fnstack_push("three");
	ck_assert_str_eq("three", fnstack_peek());
	fnstack_push("four");
	ck_assert_str_eq("four", fnstack_peek());
	fnstack_push("five");
	ck_assert_str_eq("five", fnstack_peek());
	fnstack_push("six");
	ck_assert_str_eq("six", fnstack_peek());
	fnstack_push("seven");
	ck_assert_str_eq("seven", fnstack_peek());
	fnstack_push("eight");
	ck_assert_str_eq("eight", fnstack_peek());

	/* 8 slots max because there's no point in reallocating */
	fnstack_push("nine");
	ck_assert_ptr_eq(NULL, fnstack_peek());
	fnstack_push("ten");
	ck_assert_ptr_eq(NULL, fnstack_peek());
	fnstack_pop(); /* pop 10 */
	ck_assert_ptr_eq(NULL, fnstack_peek());

	fnstack_pop(); /* pop 9 */
	ck_assert_str_eq("eight", fnstack_peek());
	fnstack_pop();
	ck_assert_str_eq("seven", fnstack_peek());
	fnstack_pop();
	ck_assert_str_eq("six", fnstack_peek());
	fnstack_pop();
	ck_assert_str_eq("five", fnstack_peek());
	fnstack_pop();
	ck_assert_str_eq("four", fnstack_peek());
	fnstack_pop();
	ck_assert_str_eq("three", fnstack_peek());
	fnstack_pop();
	ck_assert_str_eq("two", fnstack_peek());
	fnstack_pop();
	ck_assert_str_eq("one", fnstack_peek());
	fnstack_pop();
	ck_assert_ptr_eq(NULL, fnstack_peek());
}
END_TEST

START_TEST(underflow)
{
	fnstack_init();

	ck_assert_ptr_eq(NULL, fnstack_peek());
	fnstack_pop(); /* length -1 */
	ck_assert_ptr_eq(NULL, fnstack_peek());
	fnstack_pop(); /* length -2 */
	ck_assert_ptr_eq(NULL, fnstack_peek());
	fnstack_pop(); /* length -3 */
	ck_assert_ptr_eq(NULL, fnstack_peek());

	fnstack_push("-two");
	ck_assert_ptr_eq(NULL, fnstack_peek());
	fnstack_push("-one");
	ck_assert_ptr_eq(NULL, fnstack_peek());
	fnstack_push("zero");
	ck_assert_ptr_eq(NULL, fnstack_peek());

	fnstack_push("one");
	ck_assert_str_eq("one", fnstack_peek());
	fnstack_push("two");
	ck_assert_str_eq("two", fnstack_peek());
	fnstack_pop();
	ck_assert_str_eq("one", fnstack_peek());
	fnstack_pop();
	ck_assert_ptr_eq(NULL, fnstack_peek());

	fnstack_pop();
	ck_assert_ptr_eq(NULL, fnstack_peek());
	fnstack_pop();
	ck_assert_ptr_eq(NULL, fnstack_peek());
}
END_TEST

static Suite *
create_suite(void)
{
	Suite *suite;
	TCase *core;

	core = tcase_create("Core");
	tcase_add_test(core, reuse);
	tcase_add_test(core, overflow);
	tcase_add_test(core, underflow);

	suite = suite_create("Filename Stack");
	suite_add_tcase(suite, core);
	return suite;
}

int
main(void)
{
	SRunner *runner;
	int tests_failed;

	fnstack_setup();

	runner = srunner_create(create_suite());
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
