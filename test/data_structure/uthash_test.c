#include <check.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#include "data_structure/uthash.h"

struct uthash_node {
	int key;
	UT_hash_handle hh;
};

struct uthash_table {
	struct uthash_node *nodes;
};

static void
check_table(struct uthash_table *table, unsigned int argcount, ...)
{
	static bool expected[100];
	static bool iterated[100];
	va_list args;
	struct uthash_node *node;
	struct uthash_node *tmp;
	int a;

	memset(expected, 0, sizeof(expected));
	va_start(args, argcount);
	for (a = 0; a < argcount; a++)
		expected[va_arg(args, int)] = true;
	va_end(args);

	// COUNT
	ck_assert_uint_eq(argcount, HASH_COUNT(table->nodes));

	// FIND
	for (a = 0; a < argcount; a++) {
		HASH_FIND_INT(table->nodes, &a, node);
		if (expected[a]) {
			ck_assert_ptr_nonnull(node);
			ck_assert_int_eq(a, node->key);
		} else {
			ck_assert_ptr_null(node);
		}
	}

	// ITER
	memset(iterated, 0, sizeof(iterated));
	HASH_ITER(hh, table->nodes, node, tmp)
		iterated[node->key] = true;

	for (a = 0; a < argcount; a++)
		ck_assert_int_eq(expected[a], iterated[a]);
}

static void
add_node(struct uthash_table *table, int key)
{
	struct uthash_node *new;
	struct uthash_node *old;
	int error;

	new = malloc(sizeof(struct uthash_node));
	ck_assert_ptr_nonnull(new);

	memset(new, 0, sizeof(*new));
	new->key = key;

	errno = 0;
	HASH_REPLACE_INT(table->nodes, key, new, old);
	error = errno;
	ck_assert_int_eq(error, 0);

	if (old != NULL)
		free(old);
}

static void
clean_table(struct uthash_table *table)
{
	struct uthash_node *node;
	struct uthash_node *tmp;

	HASH_ITER(hh, table->nodes, node, tmp) {
		HASH_DEL(table->nodes, node);
		free(node);
	}

	ck_assert_ptr_null(table->nodes);
}

START_TEST(test_replace)
{
	struct uthash_table table;
	table.nodes = NULL;

	check_table(&table, 0);
	add_node(&table, 44);
	check_table(&table, 1, 44);
	add_node(&table, 0);
	check_table(&table, 2, 44, 0);
	add_node(&table, 99);
	check_table(&table, 3, 44, 0, 99);

	add_node(&table, 44);
	check_table(&table, 3, 44, 0, 99);
	add_node(&table, 0);
	check_table(&table, 3, 44, 0, 99);
	add_node(&table, 99);
	check_table(&table, 3, 44, 0, 99);

	add_node(&table, 0);
	check_table(&table, 3, 44, 0, 99);

	clean_table(&table);
}
END_TEST

/*
 * To assure myself I can hash nodes using an rpki_uri's global field as key.
 * (Given that they're private.)
 *
 * ie. Neither the node nor the key contains the key, but the key points to it
 * somewhere else.
 */
START_TEST(test_uri)
{
	struct test2_key {
		char *outer_string;
		int something_else;
	};

	struct test2_node {
		struct test2_key *key;
		int value;
		UT_hash_handle hh;
	};

	struct test2_node *table = NULL;

	char *keystr;
	unsigned int keystrlen;
	struct test2_node *node, *node2;

	/* Try finding a nonexistent node, because paranoia */
	keystr = strdup("potato");
	keystrlen = strlen(keystr);

	HASH_FIND(hh, table, keystr, keystrlen, node);
	ck_assert_ptr_null(node);

	/* Add a node */
	node = malloc(sizeof(struct test2_node));
	node->key = malloc(sizeof(struct test2_key));
	memset(node->key, 0, sizeof(struct test2_key));
	node->key->outer_string = keystr;
	node->key->something_else = 1;

	HASH_ADD_KEYPTR(hh, table, keystr, keystrlen, node);

	/* Try finding the node using the same string */
	node2 = NULL;
	HASH_FIND(hh, table, keystr, keystrlen, node2);
	ck_assert_ptr_eq(node, node2);

	/* Try finding the node using a different (but equal) string */
	keystr = strdup("potato");
	node2 = NULL;
	HASH_FIND(hh, table, keystr, keystrlen, node2);
	ck_assert_ptr_eq(node, node2);
	free(keystr);

	/* Try finding some other string */
	keystr = strdup("potato2");
	keystrlen = strlen(keystr);
	node2 = NULL;
	HASH_FIND(hh, table, keystr, keystrlen, node2);
	ck_assert_ptr_null(node2);
	free(keystr);

	/* free the hash table contents */
	HASH_ITER(hh, table, node, node2) {
		HASH_DEL(table, node);
		free(node->key->outer_string);
		free(node->key);
		free(node);
	}
}
END_TEST

static Suite *pdu_suite(void)
{
	Suite *suite;
	TCase *core, *uri;

	core = tcase_create("simple");
	tcase_add_test(core, test_replace);

	uri = tcase_create("uri");
	tcase_add_test(uri, test_uri);

	suite = suite_create("uthash");
	suite_add_tcase(suite, core);
	suite_add_tcase(suite, uri);
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
