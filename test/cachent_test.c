#include <check.h>

#include "alloc.c"
#include "cachent.c"
#include "cache_util.c"
#include "mock.c"
#include "types/path.c"
#include "types/url.c"

static char deleted[16][6];
static unsigned int dn;

static void
__delete_node_cb(struct cache_node const *node)
{
	strcpy(deleted[dn++], node->name);
}

START_TEST(test_delete)
{
	struct cache_node *root, *a, *b;

	a = rnode(RO2UP("a"), NULL);
	dn = 0;
	cachent_delete(a);
	ck_assert_uint_eq(1, dn);
	ck_assert_str_eq("a", deleted[0]);

	a = rnode(RO2UP("a"), NULL);
	root = rnode(RE2UP, a, NULL);
	dn = 0;
	cachent_delete(a);
	ck_assert_ptr_eq(NULL, root->children);
	ck_assert_uint_eq(1, dn);
	ck_assert_str_eq("a", deleted[0]);

	dn = 0;
	cachent_delete(root);
	ck_assert_uint_eq(1, dn);
	ck_assert_str_eq("rsync", deleted[0]);

	b = rnode(RO2UP("a/b"),
		rnode(RO2UP("a/b/c"), NULL),
		rnode(RO2UP("a/b/d"), NULL),
		rnode(RO2UP("a/b/e"), NULL),
		rnode(RO2UP("a/b/f"), NULL), NULL);
	a = rnode(RO2UP("a"),
		b,
		rnode(RO2UP("a/g"),
			rnode(RO2UP("a/g/h"),
				rnode(RO2UP("a/g/h/i"), NULL), NULL),
			rnode(RO2UP("a/g/j"),
				rnode(RO2UP("a/g/j/k"), NULL), NULL),
			rnode(RO2UP("a/g/l"),
				rnode(RO2UP("a/g/l/m"), NULL), NULL),
			rnode(RO2UP("a/g/n"),
				rnode(RO2UP("a/g/n/o"), NULL), NULL), NULL), NULL);
	root = rnode(RE2UP, a, NULL);

	dn = 0;
	cachent_delete(b);
	ck_assert_int_eq(1, HASH_COUNT(a->children));
	ck_assert_str_eq("c", deleted[0]);
	ck_assert_str_eq("d", deleted[1]);
	ck_assert_str_eq("e", deleted[2]);
	ck_assert_str_eq("f", deleted[3]);
	ck_assert_str_eq("b", deleted[4]);

	dn = 0;
	cachent_delete(a);
	ck_assert_int_eq(0, HASH_COUNT(root->children));
	ck_assert_str_eq("i", deleted[0]);
	ck_assert_str_eq("h", deleted[1]);
	ck_assert_str_eq("k", deleted[2]);
	ck_assert_str_eq("j", deleted[3]);
	ck_assert_str_eq("m", deleted[4]);
	ck_assert_str_eq("l", deleted[5]);
	ck_assert_str_eq("o", deleted[6]);
	ck_assert_str_eq("n", deleted[7]);
	ck_assert_str_eq("g", deleted[8]);
	ck_assert_str_eq("a", deleted[9]);

	dn = 0;
	cachent_delete(root);
	ck_assert_uint_eq(1, dn);
	ck_assert_str_eq("rsync", deleted[0]);
}
END_TEST

static char const *expected[32];
static unsigned int e;

static bool
ck_traverse_cb(struct cache_node *node)
{
	ck_assert_str_eq(expected[e++], node->path);
	return true;
}

static void
ck_traverse(struct cache_node *root, ...)
{
	char const *path;
	unsigned int p = 0;
	va_list args;

	va_start(args, root);
	while ((path = va_arg(args, char const *)) != NULL)
		expected[p++] = path;
	va_end(args);
	expected[p] = NULL;

	e = 0;
	cachent_traverse(root, ck_traverse_cb);
	ck_assert_uint_eq(p, e);

	cachent_delete(root);
}

START_TEST(test_traverse)
{
	struct cache_node *root;

	root = NULL;
	ck_traverse(root, NULL);

	root =	rnode(RO2UP("a"), NULL);
	ck_traverse(root, "tmp/rsync/a", NULL);

	root =	rnode(RO2UP("a"),
			rnode(RO2UP("a/b"), NULL), NULL);
	ck_traverse(root, "tmp/rsync/a", "tmp/rsync/a/b", NULL);

	root =	rnode(RO2UP("a"),
			rnode(RO2UP("a/b"),
				rnode(RO2UP("a/b/c"), NULL), NULL), NULL);
	ck_traverse(root,
		"tmp/rsync/a",
		"tmp/rsync/a/b",
		"tmp/rsync/a/b/c", NULL);

	root =	rnode(RO2UP("a"),
			rnode(RO2UP("a/b"),
				rnode(RO2UP("a/b/c"), NULL),
				rnode(RO2UP("a/b/d"), NULL), NULL), NULL);
	ck_traverse(root,
		"tmp/rsync/a",
		"tmp/rsync/a/b",
		"tmp/rsync/a/b/c",
		"tmp/rsync/a/b/d", NULL);

	root =	rnode(RO2UP("a"),
			rnode(RO2UP("a/b"),
				rnode(RO2UP("a/b/c"), NULL),
				rnode(RO2UP("a/b/d"), NULL), NULL),
			rnode(RO2UP("a/e"), NULL), NULL);
	ck_traverse(root,
		"tmp/rsync/a",
		"tmp/rsync/a/b",
		"tmp/rsync/a/b/c",
		"tmp/rsync/a/b/d",
		"tmp/rsync/a/e", NULL);

	root =	rnode(RO2UP("a"),
			rnode(RO2UP("a/b"), NULL),
			rnode(RO2UP("a/c"),
				rnode(RO2UP("a/c/d"), NULL),
				rnode(RO2UP("a/c/e"), NULL), NULL), NULL);
	ck_traverse(root,
		"tmp/rsync/a",
		"tmp/rsync/a/b",
		"tmp/rsync/a/c",
		"tmp/rsync/a/c/d",
		"tmp/rsync/a/c/e", NULL);

	root =	rnode(RO2UP("a"),
			rnode(RO2UP("a/b"),
				rnode(RO2UP("a/b/c"), NULL),
				rnode(RO2UP("a/b/d"), NULL), NULL),
			rnode(RO2UP("a/e"),
				rnode(RO2UP("a/e/f"), NULL),
				rnode(RO2UP("a/e/g"), NULL), NULL), NULL);
	ck_traverse(root,
		"tmp/rsync/a",
		"tmp/rsync/a/b",
		"tmp/rsync/a/b/c",
		"tmp/rsync/a/b/d",
		"tmp/rsync/a/e",
		"tmp/rsync/a/e/f",
		"tmp/rsync/a/e/g", NULL);

	root =	rnode(RO2UP("a"),
			rnode(RO2UP("a/b"),
				rnode(RO2UP("a/b/c"), NULL),
				rnode(RO2UP("a/b/d"), NULL),
				rnode(RO2UP("a/b/e"), NULL),
				rnode(RO2UP("a/b/f"), NULL), NULL),
			rnode(RO2UP("a/g"),
				rnode(RO2UP("a/g/h"),
					rnode(RO2UP("a/g/h/i"), NULL), NULL),
				rnode(RO2UP("a/g/j"),
					rnode(RO2UP("a/g/j/k"), NULL), NULL),
				rnode(RO2UP("a/g/l"),
					rnode(RO2UP("a/g/l/m"), NULL), NULL),
				rnode(RO2UP("a/g/n"),
					rnode(RO2UP("a/g/n/o"), NULL), NULL), NULL), NULL);
	ck_traverse(root,
		"tmp/rsync/a",
		"tmp/rsync/a/b",
		"tmp/rsync/a/b/c",
		"tmp/rsync/a/b/d",
		"tmp/rsync/a/b/e",
		"tmp/rsync/a/b/f",
		"tmp/rsync/a/g",
		"tmp/rsync/a/g/h",
		"tmp/rsync/a/g/h/i",
		"tmp/rsync/a/g/j",
		"tmp/rsync/a/g/j/k",
		"tmp/rsync/a/g/l",
		"tmp/rsync/a/g/l/m",
		"tmp/rsync/a/g/n",
		"tmp/rsync/a/g/n/o", NULL);
}
END_TEST

START_TEST(test_provide)
{
	struct cache_node *rsync, *abc, *d, *e, *f, *g, *h, *ee;

	rsync = cachent_root_rsync();
	ck_assert_ptr_ne(NULL, rsync);
	ck_assert_ptr_eq(NULL, rsync->parent);
	ck_assert_str_eq("rsync://", rsync->url);
	ck_assert_str_eq("tmp/rsync", rsync->path);
	ck_assert_str_eq("rsync", rsync->name);

	/* Create branch chain from root */
	e = cachent_provide(rsync, "rsync://a.b.c/d/e");
	ck_assert_ptr_ne(NULL, e);
	ck_assert_str_eq("rsync://a.b.c/d/e", e->url);
	ck_assert_str_eq("tmp/rsync/a.b.c/d/e", e->path);
	ck_assert_str_eq("e", e->name);

	d = e->parent;
	ck_assert_ptr_ne(NULL, d);
	ck_assert_str_eq("rsync://a.b.c/d", d->url);
	ck_assert_str_eq("tmp/rsync/a.b.c/d", d->path);
	ck_assert_str_eq("d", d->name);

	abc = d->parent;
	ck_assert_ptr_ne(NULL, abc);
	ck_assert_str_eq("rsync://a.b.c", abc->url);
	ck_assert_str_eq("tmp/rsync/a.b.c", abc->path);
	ck_assert_str_eq("a.b.c", abc->name);

	ck_assert_ptr_eq(rsync, abc->parent);

	/* Find leaf from root */
	ck_assert_ptr_eq(e, cachent_provide(rsync, "rsync://a.b.c/d/e"));
	/* Find branch from root */
	ck_assert_ptr_eq(d, cachent_provide(rsync, "rsync://a.b.c/d"));
	/* Find leaf from non-root ancestor */
	ck_assert_ptr_eq(e, cachent_provide(abc, "rsync://a.b.c/d/e"));
	/* Find branch from non-root ancestor */
	ck_assert_ptr_eq(d, cachent_provide(abc, "rsync://a.b.c/d"));
	/* Find selves */
	ck_assert_ptr_eq(NULL, cachent_provide(rsync, "rsync://")); /* Illegal */
	ck_assert_ptr_eq(abc, cachent_provide(abc, "rsync://a.b.c"));
	ck_assert_ptr_eq(e, cachent_provide(e, "rsync://a.b.c/d/e"));

	/* Some not normalized noise */
	ck_assert_ptr_eq(e, cachent_provide(e, "rsync://a.b.c/d/e////"));
	ck_assert_ptr_eq(e, cachent_provide(e, "rsync://a.b.c///d/./e//"));
	ck_assert_ptr_eq(e, cachent_provide(e, "rsync://a.b.c/d/f/../e/"));

	/* Create sibling from root */
	f = cachent_provide(rsync, "rsync://a.b.c/f");
	ck_assert_ptr_ne(NULL, f);
	ck_assert_ptr_eq(abc, f->parent);
	ck_assert_str_eq("rsync://a.b.c/f", f->url);
	ck_assert_str_eq("tmp/rsync/a.b.c/f", f->path);
	ck_assert_str_eq("f", f->name);

	/* Create more than one descendant from root */
	h = cachent_provide(rsync, "rsync://a.b.c/f/g/h");
	ck_assert_ptr_ne(NULL, h);
	ck_assert_str_eq("rsync://a.b.c/f/g/h", h->url);
	ck_assert_str_eq("tmp/rsync/a.b.c/f/g/h", h->path);
	ck_assert_str_eq("h", h->name);

	g = h->parent;
	ck_assert_ptr_ne(NULL, g);
	ck_assert_ptr_eq(f, g->parent);
	ck_assert_str_eq("rsync://a.b.c/f/g", g->url);
	ck_assert_str_eq("tmp/rsync/a.b.c/f/g", g->path);
	ck_assert_str_eq("g", g->name);

	/* Try to create a conflict by prefix */
	ee = cachent_provide(rsync, "rsync://a.b.c/d/ee");
	ck_assert_ptr_ne(e, ee);
	ck_assert_ptr_eq(d, ee->parent);
	ck_assert_str_eq("rsync://a.b.c/d/ee", ee->url);
	ck_assert_str_eq("tmp/rsync/a.b.c/d/ee", ee->path);
	ck_assert_str_eq("ee", ee->name);
	ck_assert_ptr_eq(e, cachent_provide(abc, "rsync://a.b.c/d/e"));
	ck_assert_ptr_eq(ee, cachent_provide(abc, "rsync://a.b.c/d/ee"));

	/* Prefixes don't match */
	ck_assert_ptr_eq(NULL, cachent_provide(d, "rsync://a.b.c/dd"));
	ck_assert_ptr_eq(NULL, cachent_provide(d, "rsync://a.b.c/f"));
	ck_assert_ptr_eq(NULL, cachent_provide(d, "rsync://a.b.c/d/../f"));

	cachent_delete(rsync);
}
END_TEST

static Suite *thread_pool_suite(void)
{
	Suite *suite;
	TCase *traverses, *provide;

	traverses = tcase_create("traverses");
	tcase_add_test(traverses, test_delete);
	tcase_add_test(traverses, test_traverse);

	provide = tcase_create("provide");
	tcase_add_test(provide, test_provide);

	suite = suite_create("cachent");
	suite_add_tcase(suite, traverses);
	suite_add_tcase(suite, provide);

	return suite;
}

int main(void)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	suite = thread_pool_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
