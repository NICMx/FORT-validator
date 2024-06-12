#include <check.h>
#include <stdlib.h>
#include <stdio.h>

#include "alloc.c"
#include "file.c"
#include "mock.c"

static void
create_file(char const *prefix, char const *suffix)
{
	char *full_path;
	FILE *file;

	full_path = join_paths(prefix, suffix);
	ck_assert_ptr_ne(NULL, full_path);

	file = fopen(full_path, "w");
	ck_assert_ptr_ne(NULL, file);
	fclose(file);

	free(full_path);
}

static void
create_dir(char const *prefix, char const *suffix)
{
	char *full_path;

	full_path = join_paths(prefix, suffix);
	ck_assert_ptr_ne(NULL, full_path);

	ck_assert_int_eq(0, mkdir(full_path, S_IRWXU));

	free(full_path);
}

static void
__file_merge_into(char const *root, char const *src, char const *dst)
{
	char *full_src;
	char *full_dst;

	full_src = join_paths(root, src);
	ck_assert_ptr_ne(NULL, full_src);
	full_dst = join_paths(root, dst);
	ck_assert_ptr_ne(NULL, full_dst);

	ck_assert_int_eq(0, file_merge_into(full_src, full_dst));

	free(full_src);
	free(full_dst);
}

static bool
is_dots(char const *str)
{
	return (strcmp(".", str) == 0) || (strcmp("..", str) == 0);
}

static void
check_empty_dir(char const *prefix, char const *suffix)
{
	char *full_path;
	DIR *dir;
	struct dirent *child;

	full_path = join_paths(prefix, suffix);
	ck_assert_ptr_ne(NULL, full_path);

	dir = opendir(full_path);
	ck_assert_ptr_ne(NULL, dir);
	child = readdir(dir);
	ck_assert(is_dots(child->d_name));
	child = readdir(dir);
	ck_assert(is_dots(child->d_name));
	errno = 0;
	ck_assert_ptr_eq(NULL, readdir(dir));
	ck_assert_int_eq(0, errno);
	closedir(dir);

	free(full_path);
}

static void
check_file(char const *prefix, char const *suffix)
{
	char *full_path;
	struct stat st;

	full_path = join_paths(prefix, suffix);
	ck_assert_ptr_ne(NULL, full_path);

	ck_assert_int_eq(0, stat(full_path, &st));
	ck_assert_int_ne(0, S_ISREG(st.st_mode));

	free(full_path);
}

START_TEST(test_merge_empty)
{
	char *root;

	root = mkdtemp(pstrdup("/tmp/fort_test_XXXXXX"));
	ck_assert_ptr_ne(NULL, root);

	create_dir(root, "src");
	create_dir(root, "dst");

	__file_merge_into(root, "src", "dst");

	check_empty_dir(root, "dst");

	file_rm_rf(root);
	free(root);
}
END_TEST

START_TEST(test_merge_simple)
{
	char *root;

	root = mkdtemp(pstrdup("/tmp/fort_test_XXXXXX"));
	ck_assert_ptr_ne(NULL, root);

	create_dir(root, "src");
	create_file(root, "src/a");
	create_dir(root, "dst");

	__file_merge_into(root, "src", "dst");

	check_file(root, "dst/a");

	file_rm_rf(root);
	free(root);
}
END_TEST

START_TEST(test_merge_no_override)
{
	char *root;

	root = mkdtemp(pstrdup("/tmp/fort_test_XXXXXX"));
	ck_assert_ptr_ne(NULL, root);

	create_dir(root, "src");
	create_dir(root, "dst");
	create_file(root, "dst/a");

	__file_merge_into(root, "src", "dst");

	check_file(root, "dst/a");

	file_rm_rf(root);
	free(root);
}
END_TEST

START_TEST(test_merge_override)
{
	char *root;

	root = mkdtemp(pstrdup("/tmp/fort_test_XXXXXX"));
	ck_assert_ptr_ne(NULL, root);

	create_dir(root, "src");
	create_file(root, "src/a");
	create_dir(root, "dst");
	create_file(root, "dst/a");

	__file_merge_into(root, "src", "dst");

	check_file(root, "dst/a");

	file_rm_rf(root);
	free(root);
}
END_TEST

START_TEST(test_merge_dirs)
{
	char *root;

	root = mkdtemp(pstrdup("/tmp/fort_test_XXXXXX"));
	ck_assert_ptr_ne(NULL, root);

	create_dir(root, "src");
	create_file(root, "src/a");
	create_dir(root, "src/c");
	create_file(root, "src/c/m");
	create_file(root, "src/c/n");
	create_file(root, "src/e");

	create_dir(root, "dst");
	create_file(root, "dst/b");
	create_dir(root, "dst/d");
	create_file(root, "dst/d/o");
	create_file(root, "dst/d/p");

	__file_merge_into(root, "src", "dst");

	check_file(root, "dst/a");
	check_file(root, "dst/b");
	check_file(root, "dst/c/m");
	check_file(root, "dst/c/n");
	check_file(root, "dst/d/o");
	check_file(root, "dst/d/p");
	check_file(root, "dst/e");

	file_rm_rf(root);
	free(root);
}
END_TEST

static Suite *xml_load_suite(void)
{
	Suite *suite;
	TCase *todo;

	todo = tcase_create("misc");
	tcase_add_test(todo, test_merge_empty);
	tcase_add_test(todo, test_merge_simple);
	tcase_add_test(todo, test_merge_no_override);
	tcase_add_test(todo, test_merge_override);
	tcase_add_test(todo, test_merge_dirs);

	suite = suite_create("file");
	suite_add_tcase(suite, todo);

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
