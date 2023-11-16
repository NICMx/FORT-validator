/* This test will create temporal directory "tmp/". Needs permissions. */

#include "cache/local_cache.c"

#include <check.h>
#include <stdarg.h>

#include "alloc.c"
#include "common.c"
#include "file.c"
#include "json_util.c"
#include "mock.c"
#include "data_structure/path_builder.c"
#include "types/uri.c"

/* Mocks */

struct rpki_cache *cache;

MOCK(state_retrieve, struct validation *, NULL, void)
MOCK(validation_cache, struct rpki_cache *, cache, struct validation *state)
MOCK(validation_tal, struct tal *, NULL, struct validation *state)
MOCK(tal_get_file_name, char const *, "test.tal", struct tal *tal)

static unsigned int dl_count; /* Times the download function was called */
static bool dl_error; /* Download should return error? */

int
rsync_download(struct rpki_uri *uri)
{
	char *cmd;
	int printed;

	dl_count++;
	if (dl_error)
		return -EINVAL;

	cmd = pmalloc(128);
	printed = snprintf(cmd, 128, "mkdir -p %s", uri_get_local(uri));
	ck_assert(printed < 128);

	ck_assert_int_eq(0, system(cmd));

	free(cmd);
	return 0;
}

int
http_download(struct rpki_uri *uri, bool *changed)
{
	char *cmd;
	int printed;
	int error;

	dl_count++;
	if (dl_error)
		return -EINVAL;

	cmd = pmalloc(128);
	printed = snprintf(cmd, 128,
	    /* "create file, but only if it's not already a directory" */
	    "test ! -d %s && install -D /dev/null %s",
	    uri_get_local(uri), uri_get_local(uri));
	ck_assert(printed < 128);

	error = system(cmd);

	free(cmd);
	return error;
}

MOCK_ABORT_INT(rrdp_update, struct rpki_uri *uri)

/* Helpers */

static const int SUCCESS = CNF_DIRECT | CNF_SUCCESS;
static const int HTTP_SUCCESS = SUCCESS | CNF_FILE;

static void
setup_test(void)
{
	ck_assert_int_eq(0, system("rm -rf tmp/"));
	dl_error = false;

	cache = cache_create("test.tal");
	ck_assert_ptr_nonnull(cache);
}

static bool
is_rsync(struct cache_node *node)
{
	while (node->parent != NULL)
		node = node->parent;
	return strcmp(node->basename, "rsync") == 0;
}

static bool
is_https(struct cache_node *node)
{
	while (node->parent != NULL)
		node = node->parent;
	return strcmp(node->basename, "https") == 0;
}

static void
__download(char const *url, enum uri_type uritype, int expected_error,
    unsigned int expected_cb_count)
{
	struct rpki_uri *uri;

	ck_assert_int_eq(0, uri_create(&uri, "test.tal", uritype, NULL, url));
	dl_count = 0;

	ck_assert_int_eq(expected_error, cache_download(cache, uri, NULL));
	ck_assert_uint_eq(expected_cb_count, dl_count);

	uri_refput(uri);
}

#define download_rsync(url, err, ecc) __download(url, UT_RSYNC, err, ecc)
#define download_https(url, err, ecc) __download(url, UT_HTTPS, err, ecc)

static struct cache_node *
__NODE(char const *basename, int flags, time_t success, time_t attempt,
       int error, ...)
{
	struct cache_node *result;
	struct cache_node *child;
	va_list args;

	result = pzalloc(sizeof(struct cache_node));
	result->basename = pstrdup(basename);
	result->flags = flags;
	result->ts_success = success;
	result->ts_attempt = attempt;
	result->error = error;

	va_start(args, error);
	while ((child = va_arg(args, struct cache_node *)) != NULL) {
		HASH_ADD_KEYPTR(hh, result->children, child->basename,
		    strlen(child->basename), child);
		child->parent = result;
	}
	va_end(args);

	return result;
}

#define NODE(bs, f, ...) __NODE(bs, f, 0, 0, __VA_ARGS__, NULL)
/* "Timed" node */
#define TNODE(bs, f, s, a, ...) __NODE(bs, f, s, a, __VA_ARGS__, NULL)

static void
actual_not_found(struct cache_node *expected, char *parent_basename)
{
	ck_abort_msg("Parent '%s' is missing child '%s'", parent_basename,
	    expected->basename);
}

static void
expected_not_found(struct cache_node *actual)
{
	ck_abort_msg("Parent '%s' has unexpected node '%s'",
	    (actual->parent == NULL) ? "root" : actual->parent->basename,
	    actual->basename);
}

static void
print_tree(struct cache_node *root, unsigned int tabs)
{
	struct cache_node *cursor, *tmp;
	unsigned int t;

	if (root == NULL)
		return;

	for (t = 0; t < tabs; t++)
		printf("\t");
	printf("%s\n", root->basename);

	HASH_ITER(hh, root->children, cursor, tmp)
		print_tree(cursor, tabs + 1);
}

static void
validate_node(struct cache_node *expected, struct cache_node *expected_parent,
    struct cache_node *actual, struct path_builder *pb)
{
	struct cache_node *expected_child, *actual_child, *tmp;

	if (expected == NULL) {
		ck_assert_ptr_eq(NULL, actual);
		return;
	}

	ck_assert_str_eq(expected->basename, actual->basename);
	ck_assert_int_eq(expected->flags, actual->flags);
	if (expected->flags & CNF_DIRECT) {
		/* ck_assert_int_ne(0, actual->ts_attempt); */
		/* ck_assert_int_eq(actual->ts_attempt, actual->ts_success); */
		if (expected->error)
			ck_assert_int_ne(0, actual->error);
		else
			ck_assert_int_eq(0, actual->error);
	} else {
		/* ck_assert_int_eq(0, actual->ts_attempt); */
		/* ck_assert_int_eq(0, actual->ts_success); */
		ck_assert_int_eq(0, actual->error);
	}
	ck_assert_ptr_eq(expected_parent, actual->parent);

	ck_assert_int_eq(0, pb_append(pb, expected->basename));

	HASH_ITER(hh, expected->children, expected_child, tmp) {
		HASH_FIND_STR(actual->children, expected_child->basename,
		    actual_child);
		if (actual_child == NULL)
			actual_not_found(expected_child, actual->basename);
		validate_node(expected_child, actual, actual_child, pb);
	}

	HASH_ITER(hh, actual->children, actual_child, tmp) {
		HASH_FIND_STR(expected->children, actual_child->basename,
		    expected_child);
		if (expected_child == NULL)
			expected_not_found(actual_child);
	}

	pb_pop(pb, true);
}

static void
search_dir(DIR *parent, char const *path, char const *name)
{
	struct dirent *file;
	int error;

	rewinddir(parent);
	FOREACH_DIR_FILE(parent, file) {
		if (S_ISDOTS(file))
			continue;

		if (strcmp(name, file->d_name) == 0)
			return;
	}

	error = errno;
	ck_assert_int_eq(0, error);

	ck_abort_msg("File %s/%s doesn't exist", path, name);
}

static void
validate_file(struct cache_node *expected, struct path_builder *pb,
    char const *tree)
{
	struct stat meta;
	DIR *dir;
	struct dirent *file;
	struct cache_node *child, *tmp;
	int error;

	if (expected == NULL) {
//		pb_append(pb, tree);
//		if (stat(pb->string, &meta) != 0) {
//			error = errno;
//			ck_assert_int_eq(ENOENT, error);
//			pb_pop(pb, true);
//			return;
//		}
//		ck_abort_msg("'%s' exists, but it shouldn't.", pb->string);
		return;
	}

	ck_assert_int_eq(0, pb_append(pb, expected->basename));

	if (is_rsync(expected)) {
		/* Currently, the unit tests do not fake rsync files */
		goto must_be_dir;

	} else if (is_https(expected)) {
		if (expected->flags & CNF_DIRECT) {
			if (expected->error == 0)
				goto must_be_file; /* Because HTTP */
			else
				goto end;
		} else {
			goto must_be_dir; /* Because HTTP */
		}
	} else {
		ck_abort_msg("Not rsync nor httpd");
	}

must_be_file:
	ck_assert_int_eq(0, stat(pb->string, &meta));
	ck_assert_int_eq(1, S_ISREG(meta.st_mode));
	goto end;

must_be_dir:
	errno = 0;
	dir = opendir(pb->string);
	error = errno;
	ck_assert_int_eq(0, error);
	ck_assert_ptr_nonnull(dir);

	FOREACH_DIR_FILE(dir, file) {
		if (S_ISDOTS(file))
			continue;

		HASH_FIND_STR(expected->children, file->d_name, child);
		if (child == NULL) {
			ck_abort_msg("file %s/%s is not supposed to exist.",
			    pb->string, file->d_name);
		}

		validate_file(child, pb, tree);
	}
	error = errno;
	ck_assert_int_eq(0, error);

	HASH_ITER(hh, expected->children, child, tmp)
		search_dir(dir, pb->string, child->basename);

	closedir(dir);
end:
	pb_pop(pb, true);
}

static void
validate_trees(struct cache_node *actual, struct cache_node *nodes,
    struct cache_node *files)
{
	struct path_builder pb;

	printf("------------------------------\n");
	printf("Expected nodes:\n");
	print_tree(nodes, 1);
	printf("Actual nodes:\n");
	print_tree(actual, 1);
	if (nodes != files) {
		printf("Expected files:\n");
		print_tree(files, 0);
	}
	printf("Actual files:\n");
	file_ls_R("tmp");

	pb_init(&pb);
	ck_assert_int_eq(0, pb_append(&pb, "tmp"));
	ck_assert_int_eq(0, pb_append(&pb, "test.tal"));

	validate_node(nodes, NULL, actual, &pb);
	validate_file(files, &pb, (actual != NULL) ? actual->basename : NULL);

	pb_cleanup(&pb);

	delete_node(nodes);
	if (nodes != files)
		delete_node(files);
}

static void
validate_tree(struct cache_node *actual, struct cache_node *expected)
{
	validate_trees(actual, expected, expected);
}

static void
set_times(struct cache_node *node, time_t tm)
{
	struct cache_node *child, *tmp;

	if (node == NULL)
		return;

	node->ts_success = tm;
	node->ts_attempt = tm;
	HASH_ITER(hh, node->children, child, tmp)
		set_times(child, tm);
}

static void
new_iteration(struct rpki_cache *cache)
{
	cache->startup_time = time(NULL);
	ck_assert_int_ne((time_t) -1, cache->startup_time);

	/* Ensure the old ts_successes and ts_attempts are outdated */
	set_times(cache->rsync, cache->startup_time - 100);
	set_times(cache->https, cache->startup_time - 100);
}

static void
cache_reset(struct rpki_cache *cache)
{
	delete_node(cache->rsync);
	cache->rsync = NULL;
	delete_node(cache->https);
	cache->https = NULL;
}

/* Tests */

START_TEST(test_cache_download_rsync)
{
	setup_test();

	download_rsync("rsync://a.b.c/d/e", 0, 1);
	validate_tree(cache->rsync,
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", 0, 0,
					NODE("e", SUCCESS, 0)))));

	/* Redownload same file, nothing should happen */
	download_rsync("rsync://a.b.c/d/e", 0, 0);
	validate_tree(cache->rsync,
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", 0, 0,
					NODE("e", SUCCESS, 0)))));

	/*
	 * For better *and* worse, rsyncs are recursive, which means if we've
	 * been recently asked to download e, we needn't bother redownloading
	 * e/f.
	 */
	download_rsync("rsync://a.b.c/d/e/f", 0, 0);
	validate_tree(cache->rsync,
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", 0, 0,
					NODE("e", SUCCESS, 0)))));

	/*
	 * The trees will *look* different, because the tree will get trimmed,
	 * while the filesystem will not.
	 */
	download_rsync("rsync://a.b.c/d", 0, 1);
	validate_trees(cache->rsync,
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0))),
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", 0, 0,
					NODE("e", 0, 0))))
	);

	download_rsync("rsync://a.b.c/e", 0, 1);
	validate_trees(cache->rsync,
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0),
				NODE("e", SUCCESS, 0))),
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", 0, 0,
					NODE("e", 0, 0)),
				NODE("e", 0, 0)))
	);

	download_rsync("rsync://x.y.z/e", 0, 1);
	validate_trees(cache->rsync,
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0),
				NODE("e", SUCCESS, 0)),
			NODE("x.y.z", 0, 0,
				NODE("e", SUCCESS, 0))),
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", 0, 0,
					NODE("e", 0, 0)),
				NODE("e", 0, 0)),
			NODE("x.y.z", 0, 0,
				NODE("e", 0, 0))));

	cache_destroy(cache);
}
END_TEST

START_TEST(test_cache_download_rsync_error)
{
	setup_test();

	dl_error = false;
	download_rsync("rsync://a.b.c/d", 0, 1);
	dl_error = true;
	download_rsync("rsync://a.b.c/e", -EINVAL, 1);
	validate_trees(cache->rsync,
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0),
				NODE("e", CNF_DIRECT, -EINVAL))),
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0))));

	/* Regardless of error, not reattempted because same iteration */
	dl_error = true;
	download_rsync("rsync://a.b.c/e", -EINVAL, 0);
	validate_trees(cache->rsync,
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0),
				NODE("e", CNF_DIRECT, -EINVAL))),
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0))));

	dl_error = false;
	download_rsync("rsync://a.b.c/e", -EINVAL, 0);
	validate_trees(cache->rsync,
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0),
				NODE("e", CNF_DIRECT, -EINVAL))),
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0))));

	cache_destroy(cache);
}
END_TEST

START_TEST(test_cache_cleanup_rsync)
{
	setup_test();

	/*
	 * First iteration: Tree is created. No prunes, because nothing's
	 * outdated.
	 */
	new_iteration(cache);
	download_rsync("rsync://a.b.c/d", 0, 1);
	download_rsync("rsync://a.b.c/e", 0, 1);
	cache_cleanup();
	validate_tree(cache->rsync,
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0),
				NODE("e", SUCCESS, 0))));

	/* One iteration with no changes, for paranoia */
	new_iteration(cache);
	download_rsync("rsync://a.b.c/d", 0, 1);
	download_rsync("rsync://a.b.c/e", 0, 1);
	cache_cleanup();
	validate_tree(cache->rsync,
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0),
				NODE("e", SUCCESS, 0))));

	/* Add one sibling */
	new_iteration(cache);
	download_rsync("rsync://a.b.c/d", 0, 1);
	download_rsync("rsync://a.b.c/e", 0, 1);
	download_rsync("rsync://a.b.c/f", 0, 1);
	cache_cleanup();
	validate_tree(cache->rsync,
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0),
				NODE("e", SUCCESS, 0),
				NODE("f", SUCCESS, 0))));

	/* Remove some branches */
	new_iteration(cache);
	download_rsync("rsync://a.b.c/d", 0, 1);
	cache_cleanup();
	validate_tree(cache->rsync,
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0))));

	/* Remove old branch and add sibling at the same time */
	new_iteration(cache);
	download_rsync("rsync://a.b.c/e", 0, 1);
	cache_cleanup();
	validate_tree(cache->rsync,
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("e", SUCCESS, 0))));

	/* Add a child to the same branch, do not update the old one */
	new_iteration(cache);
	download_rsync("rsync://a.b.c/e/f/g", 0, 1);
	cache_cleanup();
	validate_tree(cache->rsync,
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("e", SUCCESS, 0,
					NODE("f", 0, 0,
						NODE("g", SUCCESS, 0))))));

	/*
	 * Download parent, do not update child.
	 * Child's node should be deleted (because we don't need it anymore),
	 * but its file should persist (because it should be retained as its
	 * parent's descendant).
	 */
	new_iteration(cache);
	download_rsync("rsync://a.b.c/e/f", 0, 1);
	cache_cleanup();
	validate_trees(cache->rsync,
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("e", SUCCESS, 0,
					NODE("f", SUCCESS, 0)))),
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("e", SUCCESS, 0,
					NODE("f", 0, 0,
						NODE("g", SUCCESS, 0))))));

	/* Do it again. Node should die, all descendant files should persist. */
	new_iteration(cache);
	download_rsync("rsync://a.b.c/e", 0, 1);
	cache_cleanup();
	validate_trees(cache->rsync,
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("e", SUCCESS, 0))),
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("e", SUCCESS, 0,
					NODE("f", 0, 0,
						NODE("g", SUCCESS, 0))))));

	/* Empty the tree */
	new_iteration(cache);
	cache_cleanup();
	validate_tree(cache->rsync, NULL);

	/* Node exists, but file doesn't */
	printf("Tmp files:\n");
	file_ls_R("tmp");
	new_iteration(cache);
	download_rsync("rsync://a.b.c/e", 0, 1);
	download_rsync("rsync://a.b.c/f/g/h", 0, 1);

	validate_tree(cache->rsync,
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("e", SUCCESS, 0),
				NODE("f", 0, 0,
					NODE("g", 0, 0,
						NODE("h", SUCCESS, 0))))));
	ck_assert_int_eq(0, system("rm -rf tmp/test.tal/rsync/a.b.c/f/g"));
	cache_cleanup();
	validate_tree(cache->rsync,
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("e", SUCCESS, 0))));

	cache_destroy(cache);
}
END_TEST

START_TEST(test_cache_cleanup_rsync_error)
{
	setup_test();

	/* Set up */
	dl_error = false;
	download_rsync("rsync://a.b.c/d", 0, 1);
	dl_error = true;
	download_rsync("rsync://a.b.c/e", -EINVAL, 1);
	validate_trees(cache->rsync,
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0),
				NODE("e", CNF_DIRECT, -EINVAL))),
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0))));

	/*
	 * I originally intended this test to delete e because of the error,
	 * but it actually gets deleted because the file doesn't exist.
	 * Which is fine; we should test that too. We'll try d next, which
	 * does have a file.
	 */
	cache_cleanup();
	validate_tree(cache->rsync,
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0))));

	/* Fail d */
	new_iteration(cache);
	dl_error = true;
	download_rsync("rsync://a.b.c/d", -EINVAL, 1);
	validate_trees(cache->rsync,
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", CNF_DIRECT, -EINVAL))),
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0))));

	/* Clean up d because of error */
	cache_cleanup();
	validate_tree(cache->rsync, NULL);

	cache_destroy(cache);
}
END_TEST

START_TEST(test_cache_download_https)
{
	setup_test();

	/* Download *file* e. */
	download_https("https://a.b.c/d/e", 0, 1);
	validate_tree(cache->https,
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", 0, 0,
					NODE("e", HTTP_SUCCESS, 0)))));

	/* e is now a dir; need to replace it. */
	download_https("https://a.b.c/d/e/f", 0, 1);
	validate_tree(cache->https,
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", 0, 0,
					NODE("e", 0, 0,
						NODE("f", HTTP_SUCCESS, 0))))));

	/* d is now a file; need to replace it. */
	download_https("https://a.b.c/d", 0, 1);
	validate_tree(cache->https,
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0))));

	/* Download something else 1 */
	download_https("https://a.b.c/e", 0, 1);
	validate_tree(cache->https,
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0),
				NODE("e", HTTP_SUCCESS, 0))));

	/* Download something else 2 */
	download_https("https://x.y.z/e", 0, 1);
	validate_tree(cache->https,
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0),
				NODE("e", HTTP_SUCCESS, 0)),
			NODE("x.y.z", 0, 0,
				NODE("e", HTTP_SUCCESS, 0))));

	cache_destroy(cache);
}
END_TEST

START_TEST(test_cache_download_https_error)
{
	setup_test();

	dl_error = false;
	download_https("https://a.b.c/d", 0, 1);
	dl_error = true;
	download_https("https://a.b.c/e", -EINVAL, 1);
	validate_trees(cache->https,
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0),
				NODE("e", CNF_DIRECT, -EINVAL))),
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0))));

	/* Regardless of error, not reattempted because same iteration */
	dl_error = true;
	download_https("https://a.b.c/e", -EINVAL, 0);
	validate_trees(cache->https,
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0),
				NODE("e", CNF_DIRECT, -EINVAL))),
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0))));

	dl_error = false;
	download_https("https://a.b.c/e", -EINVAL, 0);
	validate_trees(cache->https,
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0),
				NODE("e", CNF_DIRECT, -EINVAL))),
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0))));

	cache_destroy(cache);
}
END_TEST

START_TEST(test_cache_cleanup_https)
{
	setup_test();

	/* First iteration; make a tree and clean it */
	new_iteration(cache);
	download_https("https://a.b.c/d", 0, 1);
	download_https("https://a.b.c/e", 0, 1);
	cache_cleanup();
	validate_tree(cache->https,
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0),
				NODE("e", HTTP_SUCCESS, 0))));

	/* Remove one branch */
	new_iteration(cache);
	download_https("https://a.b.c/d", 0, 1);
	cache_cleanup();
	validate_tree(cache->https,
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0))));

	/* Change the one branch */
	new_iteration(cache);
	download_https("https://a.b.c/e", 0, 1);
	cache_cleanup();
	validate_tree(cache->https,
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("e", HTTP_SUCCESS, 0))));

	/*
	 * Add a child to the same branch, do not update the old one
	 */
	new_iteration(cache);
	download_https("https://a.b.c/e/f/g", 0, 1);
	cache_cleanup();
	validate_tree(cache->https,
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("e", 0, 0,
					NODE("f", 0, 0,
						NODE("g", HTTP_SUCCESS, 0))))));

	/*
	 * Download parent, do not update child.
	 * Children need to die, because parent is now a file.
	 */
	new_iteration(cache);
	download_https("https://a.b.c/e/f", 0, 1);
	cache_cleanup();
	validate_tree(cache->https,
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("e", 0, 0,
					NODE("f", HTTP_SUCCESS, 0)))));

	/* Do it again. */
	new_iteration(cache);
	download_https("https://a.b.c/e", 0, 1);
	cache_cleanup();
	validate_tree(cache->https,
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("e", HTTP_SUCCESS, 0))));

	/* Empty the tree */
	new_iteration(cache);
	cache_cleanup();
	validate_tree(cache->https, NULL);

	/* Node exists, but file doesn't */
	new_iteration(cache);
	download_https("https://a.b.c/e", 0, 1);
	download_https("https://a.b.c/f/g/h", 0, 1);
	validate_tree(cache->https,
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("e", HTTP_SUCCESS, 0),
				NODE("f", 0, 0,
					NODE("g", 0, 0,
						NODE("h", HTTP_SUCCESS, 0))))));
	ck_assert_int_eq(0, system("rm -rf tmp/test.tal/https/a.b.c/f/g"));
	cache_cleanup();
	validate_tree(cache->https,
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("e", HTTP_SUCCESS, 0))));

	cache_destroy(cache);
}
END_TEST

START_TEST(test_cache_cleanup_https_error)
{
	setup_test();

	/* Set up */
	dl_error = false;
	download_https("https://a.b.c/d", 0, 1);
	dl_error = true;
	download_https("https://a.b.c/e", -EINVAL, 1);
	validate_trees(cache->https,
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0),
				NODE("e", CNF_DIRECT, -EINVAL))),
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0))));

	/* Deleted because file ENOENT. */
	cache_cleanup();
	validate_tree(cache->https,
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0))));

	/* Fail d */
	new_iteration(cache);
	dl_error = true;
	download_https("https://a.b.c/d", -EINVAL, 1);
	validate_trees(cache->https,
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", CNF_DIRECT, -EINVAL))),
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0))));

	/* Clean up d because of error */
	cache_cleanup();
	validate_tree(cache->https, NULL);

	cache_destroy(cache);
}
END_TEST

START_TEST(test_dots)
{
	setup_test();

	download_https("https://a.b.c/d", 0, 1);
	validate_tree(cache->https,
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0))));

	download_https("https://a.b.c/d/.", 0, 0);
	validate_tree(cache->https,
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0))));

	download_https("https://a.b.c/d/..", 0, 1);
	validate_tree(cache->https,
		NODE("https", 0, 0,
			NODE("a.b.c", HTTP_SUCCESS, 0)));

	download_https("https://a.b.c/./d/../e", 0, 1);
	validate_tree(cache->https,
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("e", HTTP_SUCCESS, 0))));

	cache_destroy(cache);
}
END_TEST

START_TEST(test_metadata_json)
{
	const time_t NOW = 1693952610;
	json_t *json;
	char *str;

	setup_test();

	ck_assert_int_eq(0, system("rm -rf tmp/"));
	ck_assert_int_eq(0, system("mkdir -p tmp/test.tal"));

	cache->rsync = TNODE("rsync", 0, NOW + 0, NOW + 1, 0,
			TNODE("a.b.c", 0, NOW + 2, NOW + 3, 0,
				TNODE("d", SUCCESS, NOW + 4, NOW + 5, 0),
				TNODE("e", CNF_DIRECT, NOW + 6, NOW + 7, 1)),
			TNODE("x.y.z", 0, NOW + 8, NOW + 9, 0,
				TNODE("w", SUCCESS, NOW + 0, NOW + 1, 0)));
	cache->https = TNODE("https", 0, NOW + 2, NOW + 3, 0,
			TNODE("a", 0, NOW + 4, NOW + 5, 0,
				TNODE("b", HTTP_SUCCESS, NOW + 6, NOW + 7, 1),
				TNODE("c", HTTP_SUCCESS, NOW + 8, NOW + 9, 0)));

	json = build_metadata_json(cache);
	ck_assert_int_eq(0, json_dump_file(json, "tmp/test.tal/metadata.json", JSON_COMPACT));

	str = json_dumps(json, /* JSON_INDENT(4) */ JSON_COMPACT);
	/* printf("%s\n", str); */
	json_decref(json);

	/* TODO (test) Time zones are hardcoded to CST */
	ck_assert_str_eq(
		"[{\"basename\":\"rsync\",\"children\":["
			"{\"basename\":\"a.b.c\",\"children\":["
				"{\"basename\":\"d\",\"direct-download\":true,\"latest-result\":0,\"attempt-timestamp\":\"2023-09-05T16:23:35-0600\",\"successful-download\":true,\"success-timestamp\":\"2023-09-05T16:23:34-0600\"},"
				"{\"basename\":\"e\",\"direct-download\":true,\"latest-result\":1,\"attempt-timestamp\":\"2023-09-05T16:23:37-0600\"}]},"
			"{\"basename\":\"x.y.z\",\"children\":["
				"{\"basename\":\"w\",\"direct-download\":true,\"latest-result\":0,\"attempt-timestamp\":\"2023-09-05T16:23:31-0600\",\"successful-download\":true,\"success-timestamp\":\"2023-09-05T16:23:30-0600\"}]}]},"
		"{\"basename\":\"https\",\"children\":["
			"{\"basename\":\"a\",\"children\":["
				"{\"basename\":\"b\",\"direct-download\":true,\"latest-result\":1,\"attempt-timestamp\":\"2023-09-05T16:23:37-0600\",\"successful-download\":true,\"success-timestamp\":\"2023-09-05T16:23:36-0600\",\"is-file\":true},"
				"{\"basename\":\"c\",\"direct-download\":true,\"latest-result\":0,\"attempt-timestamp\":\"2023-09-05T16:23:39-0600\",\"successful-download\":true,\"success-timestamp\":\"2023-09-05T16:23:38-0600\",\"is-file\":true}]}]}]",
		str);
	free(str);

	cache_reset(cache);

	load_metadata_json(cache);
	ck_assert_ptr_nonnull(cache->rsync);
	ck_assert_ptr_nonnull(cache->https);

	validate_trees(cache->rsync,
		TNODE("rsync", 0, 0, 0, 0,
			TNODE("a.b.c", 0, 0, 0, 0,
				TNODE("d", SUCCESS, NOW + 4, NOW + 5, 0),
				TNODE("e", CNF_DIRECT, NOW + 6, NOW + 7, 1)),
			TNODE("x.y.z", 0, 0, 0, 0,
				TNODE("w", SUCCESS, NOW + 0, NOW + 1, 0))),
		NULL);
	validate_trees(cache->https,
		TNODE("https", 0, 0, 0, 0,
			TNODE("a", 0, 0, 0, 0,
				TNODE("b", HTTP_SUCCESS, NOW + 6, NOW + 7, 1),
				TNODE("c", HTTP_SUCCESS, NOW + 8, NOW + 9, 0))),
		NULL);

	cache_destroy(cache);
}
END_TEST

#define INIT(_root)							\
	pb_init(&pb);							\
	root = _root;							\
	ctt_init(&ctt, cache, &root, &pb)
#define DONE								\
	delete_node(root);						\
	pb_cleanup(&pb)

#define ASSERT_NEXT_NODE(_basename, _path)				\
	node = ctt_next(&ctt);						\
	ck_assert_ptr_ne(NULL, node);					\
	ck_assert_str_eq(_basename, node->basename);			\
	ck_assert_str_eq(_path, pb.string)
#define ASSERT_NEXT_NULL	ck_assert_ptr_eq(NULL, ctt_next(&ctt))
#define ASSERT_TREE(_root)	validate_trees(root, _root, NULL)

#define BRANCH(bn, ...) __NODE(bn, 0, 0, 0, 0, __VA_ARGS__, NULL)
#define LEAF(bn) __NODE(bn, CNF_DIRECT, now, now, 0, NULL)

START_TEST(test_ctt_traversal)
{
	struct cache_tree_traverser ctt;
	struct path_builder pb;
	struct cache_node *root;
	struct cache_node *node;
	time_t now;

	setup_test();

	now = time(NULL);
	ck_assert_int_ne((time_t) -1, now);

	INIT(LEAF("a"));
	ASSERT_NEXT_NODE("a", "a");
	ASSERT_NEXT_NULL;
	ASSERT_TREE(LEAF("a"));
	DONE;

	INIT(BRANCH("a", LEAF("b")));
	ASSERT_NEXT_NODE("b", "a/b");
	ASSERT_NEXT_NODE("a", "a");
	ASSERT_NEXT_NULL;
	ASSERT_TREE(BRANCH("a", LEAF("b")));
	DONE;

	INIT(BRANCH("a",
		BRANCH("b",
			BRANCH("c",
				LEAF("d")))));
	ASSERT_NEXT_NODE("d", "a/b/c/d");
	ASSERT_NEXT_NODE("c", "a/b/c");
	ASSERT_NEXT_NODE("b", "a/b");
	ASSERT_NEXT_NODE("a", "a");
	ASSERT_NEXT_NULL;
	ASSERT_TREE(BRANCH("a",
			BRANCH("b",
				BRANCH("c",
					LEAF("d")))));
	DONE;

	INIT(BRANCH("a",
		LEAF("b"),
		BRANCH("c",
			LEAF("d")),
		LEAF("e")));
	ASSERT_NEXT_NODE("b", "a/b");
	ASSERT_NEXT_NODE("d", "a/c/d");
	ASSERT_NEXT_NODE("c", "a/c");
	ASSERT_NEXT_NODE("e", "a/e");
	ASSERT_NEXT_NODE("a", "a");
	ASSERT_NEXT_NULL;
	ASSERT_TREE(BRANCH("a",
			LEAF("b"),
			BRANCH("c",
				LEAF("d")),
			LEAF("e")));
	DONE;

	INIT(BRANCH("a",
		BRANCH("b",
			LEAF("c")),
		BRANCH("d",
			LEAF("e")),
		BRANCH("f",
			LEAF("g"))));
	ASSERT_NEXT_NODE("c", "a/b/c");
	ASSERT_NEXT_NODE("b", "a/b");
	ASSERT_NEXT_NODE("e", "a/d/e");
	ASSERT_NEXT_NODE("d", "a/d");
	ASSERT_NEXT_NODE("g", "a/f/g");
	ASSERT_NEXT_NODE("f", "a/f");
	ASSERT_NEXT_NODE("a", "a");
	ASSERT_NEXT_NULL;
	ASSERT_TREE(BRANCH("a",
			BRANCH("b",
				LEAF("c")),
			BRANCH("d",
				LEAF("e")),
			BRANCH("f",
				LEAF("g"))));
	DONE;

	INIT(BRANCH("a",
		BRANCH("b",
			LEAF("c")),
		BRANCH("d",
			LEAF("e")),
		BRANCH("f",
			BRANCH("g", NULL))));
	ASSERT_NEXT_NODE("c", "a/b/c");
	ASSERT_NEXT_NODE("b", "a/b");
	ASSERT_NEXT_NODE("e", "a/d/e");
	ASSERT_NEXT_NODE("d", "a/d");
	ASSERT_NEXT_NODE("a", "a");
	ASSERT_NEXT_NULL;
	ASSERT_TREE(BRANCH("a",
			BRANCH("b",
				LEAF("c")),
			BRANCH("d",
				LEAF("e"))));
	DONE;

	INIT(NULL);
	ASSERT_NEXT_NULL;
	ck_assert_ptr_eq(NULL, root);
	DONE;

	INIT(BRANCH("a", NULL));
	ASSERT_NEXT_NULL;
	ck_assert_ptr_eq(NULL, root);
	DONE;

	INIT(BRANCH("a",
		BRANCH("b", NULL),
		BRANCH("c", NULL),
		BRANCH("d", NULL)));
	ASSERT_NEXT_NULL;
	ck_assert_ptr_eq(NULL, root);
	DONE;

	cache_destroy(cache);
}
END_TEST

static void
prepare_uri_list(struct uri_list *uris, ...)
{
	char const *str;
	enum uri_type type;
	struct rpki_uri *uri;
	va_list args;

	uris_init(uris);

	va_start(args, uris);
	while ((str = va_arg(args, char const *)) != NULL) {
		if (str_starts_with(str, "https://"))
			type = UT_HTTPS;
		else if (str_starts_with(str, "rsync://"))
			type = UT_RSYNC;
		else
			ck_abort_msg("Bad protocol: %s", str);
		ck_assert_int_eq(0, uri_create(&uri, "test.tal", type, NULL, str));
		uris_add(uris, uri);
	}
	va_end(args);
}

#define PREPARE_URI_LIST(uris, ...) prepare_uri_list(uris, ##__VA_ARGS__, NULL)

START_TEST(test_recover)
{
	struct uri_list uris;

	setup_test();

	/* Query on empty database */
	PREPARE_URI_LIST(&uris, "rsync://a.b.c/d", "https://a.b.c/d");
	ck_assert_ptr_null(cache_recover(cache, &uris, false));
	uris_cleanup(&uris);

	/* Only first URI is cached */
	cache_reset(cache);
	download_rsync("rsync://a/b/c", 0, 1);

	PREPARE_URI_LIST(&uris, "rsync://a/b/c", "https://d/e", "https://f");
	ck_assert_ptr_eq(uris.array[0], cache_recover(cache, &uris, false));
	uris_cleanup(&uris);

	/* Only second URI is cached */
	cache_reset(cache);
	download_https("https://d/e", 0, 1);

	PREPARE_URI_LIST(&uris, "rsync://a/b/c", "https://d/e", "https://f");
	ck_assert_ptr_eq(uris.array[1], cache_recover(cache, &uris, false));
	uris_cleanup(&uris);

	/* Only third URI is cached */
	cache_reset(cache);
	download_https("https://f", 0, 1);

	PREPARE_URI_LIST(&uris, "rsync://a/b/c", "https://d/e", "https://f");
	ck_assert_ptr_eq(uris.array[2], cache_recover(cache, &uris, false));
	uris_cleanup(&uris);

	/* None was cached */
	cache_reset(cache);
	download_rsync("rsync://d/e", 0, 1);

	PREPARE_URI_LIST(&uris, "rsync://a/b/c", "https://d/e", "https://f");
	ck_assert_ptr_null(cache_recover(cache, &uris, false));
	uris_cleanup(&uris);

	/*
	 * At present, cache_recover() can only be called after all of a
	 * download's URLs yielded failure.
	 * However, node.error can still be zero. This happens when the download
	 * was successful, but the RRDP code wasn't able to expand the snapshot
	 * or deltas.
	 */
	cache_reset(cache);
	cache->rsync = NODE("rsync", 0, 0,
		NODE("a", 0, 0,
			TNODE("1", SUCCESS, 100, 100, 0),
			TNODE("2", SUCCESS, 100, 100, 1),
			TNODE("3", SUCCESS, 100, 200, 0),
			TNODE("4", SUCCESS, 100, 200, 1),
			TNODE("5", SUCCESS, 200, 100, 0),
			TNODE("6", SUCCESS, 200, 100, 1)),
		NODE("b", 0, 0,
			TNODE("1", CNF_DIRECT, 100, 100, 0),
			TNODE("2", CNF_DIRECT, 100, 100, 1),
			TNODE("3", CNF_DIRECT, 100, 200, 0),
			TNODE("4", CNF_DIRECT, 100, 200, 1),
			TNODE("5", CNF_DIRECT, 200, 100, 0),
			TNODE("6", CNF_DIRECT, 200, 100, 1)),
		TNODE("c", SUCCESS, 300, 300, 0,
			TNODE("1", 0, 0, 0, 0)),
		TNODE("d", SUCCESS, 50, 50, 0,
			TNODE("1", 0, 0, 0, 0)));

	/* Multiple successful caches: Prioritize the most recent one */
	PREPARE_URI_LIST(&uris, "rsync://a/1", "rsync://a/3", "rsync://a/5");
	ck_assert_ptr_eq(uris.array[2], cache_recover(cache, &uris, false));
	uris_cleanup(&uris);

	PREPARE_URI_LIST(&uris, "rsync://a/5", "rsync://a/1", "rsync://a/3");
	ck_assert_ptr_eq(uris.array[0], cache_recover(cache, &uris, false));
	uris_cleanup(&uris);

	/* No successful caches: No viable candidates */
	PREPARE_URI_LIST(&uris, "rsync://b/2", "rsync://b/4", "rsync://b/6");
	ck_assert_ptr_null(cache_recover(cache, &uris, false));
	uris_cleanup(&uris);

	/* Status: CNF_SUCCESS is better than 0. */
	PREPARE_URI_LIST(&uris, "rsync://b/1", "rsync://a/1");
	ck_assert_ptr_eq(uris.array[1], cache_recover(cache, &uris, false));
	uris_cleanup(&uris);

	/*
	 * If CNF_SUCCESS && error, Fort will probably run into a problem
	 * reading the cached directory, because it's either outdated or
	 * recently corrupted.
	 * But it should still TRY to read it, as there's a chance the
	 * outdatedness is not that severe.
	 */
	PREPARE_URI_LIST(&uris, "rsync://a/2", "rsync://b/2");
	ck_assert_ptr_eq(uris.array[0], cache_recover(cache, &uris, false));
	uris_cleanup(&uris);

	/* Parents of downloaded nodes */
	PREPARE_URI_LIST(&uris, "rsync://a", "rsync://b");
	ck_assert_ptr_null(cache_recover(cache, &uris, false));
	uris_cleanup(&uris);

	/* Children of downloaded nodes */
	PREPARE_URI_LIST(&uris, "rsync://a/5", "rsync://c/1");
	ck_assert_ptr_eq(uris.array[1], cache_recover(cache, &uris, false));
	uris_cleanup(&uris);

	PREPARE_URI_LIST(&uris, "rsync://a/5", "rsync://c/2");
	ck_assert_ptr_eq(uris.array[1], cache_recover(cache, &uris, false));
	uris_cleanup(&uris);

	PREPARE_URI_LIST(&uris, "rsync://a/1", "rsync://d/1");
	ck_assert_ptr_eq(uris.array[0], cache_recover(cache, &uris, false));
	uris_cleanup(&uris);

	PREPARE_URI_LIST(&uris, "rsync://a/1", "rsync://d/2");
	ck_assert_ptr_eq(uris.array[0], cache_recover(cache, &uris, false));
	uris_cleanup(&uris);

	/* Try them all at the same time */
	PREPARE_URI_LIST(&uris,
	    "rsync://a", "rsync://a/1", "rsync://a/2", "rsync://a/3",
	    "rsync://a/4", "rsync://a/5", "rsync://a/6",
	    "rsync://b", "rsync://b/1", "rsync://b/2", "rsync://b/3",
	    "rsync://b/4", "rsync://b/5", "rsync://b/6",
	    "rsync://c/2", "rsync://d/1", "rsync://e/1");
	ck_assert_ptr_eq(uris.array[14], cache_recover(cache, &uris, false));
	uris_cleanup(&uris);


	struct uri_and_node un = { 0 };

	cache_reset(cache);
	cache->rsync = NODE("rsync", 0, 0,
		TNODE("1", CNF_SUCCESS, 200, 200, 0,
			TNODE("2", CNF_DIRECT, 200, 200, 1,
				TNODE("3", SUCCESS, 100, 100, 1,
					TNODE("4", SUCCESS, 200, 200, 1,
						TNODE("5", SUCCESS, 100, 100, 0,
							TNODE("6", SUCCESS, 200, 200, 0)))))));

	/* Try them all at the same time */
	PREPARE_URI_LIST(&uris, "rsync://1/2/3/4/5/6");
	__cache_recover(cache, &uris, false, &un);
	ck_assert_ptr_eq(uris.array[0], un.uri);
	ck_assert_str_eq("6", un.node->basename);
	uris_cleanup(&uris);

	/* TODO (test) HTTP (non-recursive) */
	/* TODO (test) more variations */
	/* TODO (test) node with DIRECT, then not direct, then DIRECT */

	cache_destroy(cache);
}
END_TEST

/* Boilerplate */

Suite *thread_pool_suite(void)
{
	Suite *suite;
	TCase *rsync , *https, *dot, *meta, *ctt;

	rsync = tcase_create("rsync");
	tcase_add_test(rsync, test_cache_download_rsync);
	tcase_add_test(rsync, test_cache_download_rsync_error);
	tcase_add_test(rsync, test_cache_cleanup_rsync);
	tcase_add_test(rsync, test_cache_cleanup_rsync_error);

	https = tcase_create("https");
	tcase_add_test(https, test_cache_download_https);
	tcase_add_test(https, test_cache_download_https_error);
	tcase_add_test(https, test_cache_cleanup_https);
	tcase_add_test(https, test_cache_cleanup_https_error);

	dot = tcase_create("dot");
	tcase_add_test(dot, test_dots);

	meta = tcase_create("metadata.json");
	tcase_add_test(meta, test_metadata_json);

	ctt = tcase_create("ctt");
	tcase_add_test(ctt, test_ctt_traversal);

	ctt = tcase_create("recover");
	tcase_add_test(ctt, test_recover);

	suite = suite_create("local-cache");
	suite_add_tcase(suite, rsync);
	suite_add_tcase(suite, https);
	suite_add_tcase(suite, dot);
	suite_add_tcase(suite, meta);
	suite_add_tcase(suite, ctt);

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
