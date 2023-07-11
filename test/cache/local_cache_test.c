/* This test will create temporal directory "tmp/". Needs permissions. */

#include "cache/local_cache.c"

#include <check.h>
#include <stdarg.h>

#include "alloc.c"
#include "common.c"
#include "file.c"
#include "mock.c"
#include "data_structure/path_builder.c"
#include "types/uri.c"

/* Mocks */

MOCK_ABORT_PTR(state_retrieve, validation, void)

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
	printed = snprintf(cmd, 128, "mkdir -p tmp/%s", uri_get_local(uri));
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
	    "test ! -d tmp/%s && install -D /dev/null tmp/%s",
	    uri_get_local(uri), uri_get_local(uri));
	ck_assert(printed < 128);

	error = system(cmd);

	free(cmd);
	return error;
}

/* Helpers */

static const int SUCCESS = CNF_DIRECT | CNF_SUCCESS;
static const int HTTP_SUCCESS = SUCCESS | CNF_FILE;

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

	ck_assert_int_eq(0, uri_create(&uri, uritype, url));
	dl_count = 0;

	ck_assert_int_eq(expected_error, cache_download(uri, NULL));
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

	path_append(pb, expected->basename);

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

	path_pop(pb, true);
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
validate_file(struct cache_node *expected, struct path_builder *pb)
{
	char const *path;
	struct stat meta;
	DIR *dir;
	struct dirent *file;
	struct cache_node *child, *tmp;
	int error;

	if (expected == NULL)
		return;

	path_append(pb, expected->basename);
	ck_assert_int_eq(0, path_peek(pb, &path));

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
	ck_assert_int_eq(0, stat(path, &meta));
	ck_assert_int_eq(1, S_ISREG(meta.st_mode));
	goto end;

must_be_dir:
	errno = 0;
	dir = opendir(path);
	error = errno;
	ck_assert_int_eq(0, error);
	ck_assert_ptr_nonnull(dir);

	FOREACH_DIR_FILE(dir, file) {
		if (S_ISDOTS(file))
			continue;

		HASH_FIND_STR(expected->children, file->d_name, child);
		if (child == NULL) {
			ck_abort_msg("file %s/%s is not supposed to exist.",
			    path, file->d_name);
		}

		validate_file(child, pb);
	}
	error = errno;
	ck_assert_int_eq(0, error);

	HASH_ITER(hh, expected->children, child, tmp)
		search_dir(dir, path, child->basename);

	closedir(dir);
end:
	path_pop(pb, true);
}

static void
validate_trees(struct cache_node *nodes, struct cache_node *files)
{
	struct cache_node *actual;
	struct path_builder pb;

	if (is_rsync(nodes))
		actual = rsync;
	else if (is_https(nodes))
		actual = https;
	else
		ck_abort_msg("unknown root node: %s", nodes->basename);

	printf("------------------------------\n");
	printf("Expected nodes:\n");
	print_tree(nodes, 1);
	printf("Actual nodes:\n");
	print_tree(actual, 1);
	if (files != NULL) {
		if (nodes != files) {
			printf("Expected files:\n");
			print_tree(files, 0);
		}
		printf("Actual files:\n");
		file_ls_R("tmp");
	}

	path_init(&pb);
	path_append(&pb, "tmp");

	validate_node(nodes, NULL, actual, &pb);
	validate_file(files, &pb);

	path_cancel(&pb);

	destroy_tree(nodes);
	if (nodes != files)
		destroy_tree(files);
}

static void
validate_tree(struct cache_node *expected)
{
	validate_trees(expected, expected);
}

static void
backtrack_times(struct cache_node *node)
{
	struct cache_node *child, *tmp;
	node->ts_success -= 1000;
	node->ts_attempt -= 1000;
	HASH_ITER(hh, node->children, child, tmp)
		backtrack_times(child);
}

static void
__cache_prepare(void)
{
	cache_prepare();
	/* Ensure the old ts_successes and ts_attempts are outdated */
	backtrack_times(rsync);
	backtrack_times(https);
}

/* Tests */

START_TEST(test_cache_download_rsync)
{
	ck_assert_int_eq(0, system("rm -rf tmp/"));
	dl_error = false;

	cache_prepare();

	download_rsync("rsync://a.b.c/d/e", 0, 1);
	validate_tree(
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", 0, 0,
					NODE("e", SUCCESS, 0)))));

	/* Redownload same file, nothing should happen */
	download_rsync("rsync://a.b.c/d/e", 0, 0);
	validate_tree(
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
	validate_tree(
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", 0, 0,
					NODE("e", SUCCESS, 0)))));

	/*
	 * The trees will *look* different, because the tree will get trimmed,
	 * while the filesystem will not.
	 */
	download_rsync("rsync://a.b.c/d", 0, 1);
	validate_trees(
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0))),
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", 0, 0,
					NODE("e", 0, 0))))
	);

	download_rsync("rsync://a.b.c/e", 0, 1);
	validate_trees(
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
	validate_trees(
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

	cache_teardown();
}
END_TEST

START_TEST(test_cache_download_rsync_error)
{
	ck_assert_int_eq(0, system("rm -rf tmp/"));

	cache_prepare();

	dl_error = false;
	download_rsync("rsync://a.b.c/d", 0, 1);
	dl_error = true;
	download_rsync("rsync://a.b.c/e", -EINVAL, 1);
	validate_trees(
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
	validate_trees(
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0),
				NODE("e", CNF_DIRECT, -EINVAL))),
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0))));

	dl_error = false;
	download_rsync("rsync://a.b.c/e", -EINVAL, 0);
	validate_trees(
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0),
				NODE("e", CNF_DIRECT, -EINVAL))),
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0))));

	cache_teardown();
}
END_TEST

START_TEST(test_cache_cleanup_rsync)
{
	ck_assert_int_eq(0, system("rm -rf tmp/"));
	dl_error = false;

	/*
	 * First iteration: Tree is created. No prunes, because nothing's
	 * outdated.
	 */
	__cache_prepare();
	download_rsync("rsync://a.b.c/d", 0, 1);
	download_rsync("rsync://a.b.c/e", 0, 1);
	cache_cleanup();
	validate_tree(
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0),
				NODE("e", SUCCESS, 0))));

	/* One iteration with no changes, for paranoia */
	__cache_prepare();
	download_rsync("rsync://a.b.c/d", 0, 1);
	download_rsync("rsync://a.b.c/e", 0, 1);
	cache_cleanup();
	validate_tree(
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0),
				NODE("e", SUCCESS, 0))));

	/* Add one sibling */
	__cache_prepare();
	download_rsync("rsync://a.b.c/d", 0, 1);
	download_rsync("rsync://a.b.c/e", 0, 1);
	download_rsync("rsync://a.b.c/f", 0, 1);
	cache_cleanup();
	validate_tree(
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0),
				NODE("e", SUCCESS, 0),
				NODE("f", SUCCESS, 0))));

	/* Remove some branches */
	__cache_prepare();
	download_rsync("rsync://a.b.c/d", 0, 1);
	cache_cleanup();
	validate_tree(
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0))));

	/* Remove old branch and add sibling at the same time */
	__cache_prepare();
	download_rsync("rsync://a.b.c/e", 0, 1);
	cache_cleanup();
	validate_tree(
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("e", SUCCESS, 0))));

	/* Add a child to the same branch, do not update the old one */
	__cache_prepare();
	download_rsync("rsync://a.b.c/e/f/g", 0, 1);
	cache_cleanup();
	validate_tree(
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
	__cache_prepare();
	download_rsync("rsync://a.b.c/e/f", 0, 1);
	cache_cleanup();
	validate_trees(
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
	__cache_prepare();
	download_rsync("rsync://a.b.c/e", 0, 1);
	cache_cleanup();
	validate_trees(
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("e", SUCCESS, 0))),
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("e", SUCCESS, 0,
					NODE("f", 0, 0,
						NODE("g", SUCCESS, 0))))));

	/* Empty the tree */
	__cache_prepare();
	cache_cleanup();
	validate_tree(NODE("rsync", 0, 0));

	/* Node exists, but file doesn't */
	__cache_prepare();
	download_rsync("rsync://a.b.c/e", 0, 1);
	download_rsync("rsync://a.b.c/f/g/h", 0, 1);
	validate_tree(
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("e", SUCCESS, 0),
				NODE("f", 0, 0,
					NODE("g", 0, 0,
						NODE("h", SUCCESS, 0))))));
	ck_assert_int_eq(0, system("rm -rf tmp/rsync/a.b.c/f/g"));
	cache_cleanup();
	validate_tree(
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("e", SUCCESS, 0))));

	cache_teardown();
}
END_TEST

START_TEST(test_cache_cleanup_rsync_error)
{
	ck_assert_int_eq(0, system("rm -rf tmp/"));

	cache_prepare();

	/* Set up */
	dl_error = false;
	download_rsync("rsync://a.b.c/d", 0, 1);
	dl_error = true;
	download_rsync("rsync://a.b.c/e", -EINVAL, 1);
	validate_trees(
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
	validate_tree(
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0))));

	/* Fail d */
	__cache_prepare();
	dl_error = true;
	download_rsync("rsync://a.b.c/d", -EINVAL, 1);
	validate_trees(
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", CNF_DIRECT, -EINVAL))),
		NODE("rsync", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", SUCCESS, 0))));

	/* Clean up d because of error */
	cache_cleanup();
	validate_tree(NODE("rsync", 0, 0));

	cache_teardown();
}
END_TEST

START_TEST(test_cache_download_https)
{
	ck_assert_int_eq(0, system("rm -rf tmp/"));
	dl_error = false;

	cache_prepare();

	/* Download *file* e. */
	download_https("https://a.b.c/d/e", 0, 1);
	validate_tree(
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", 0, 0,
					NODE("e", HTTP_SUCCESS, 0)))));

	/* e is now a dir; need to replace it. */
	download_https("https://a.b.c/d/e/f", 0, 1);
	validate_tree(
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", 0, 0,
					NODE("e", 0, 0,
						NODE("f", HTTP_SUCCESS, 0))))));

	/* d is now a file; need to replace it. */
	download_https("https://a.b.c/d", 0, 1);
	validate_tree(
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0))));

	/* Download something else 1 */
	download_https("https://a.b.c/e", 0, 1);
	validate_tree(
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0),
				NODE("e", HTTP_SUCCESS, 0))));

	/* Download something else 2 */
	download_https("https://x.y.z/e", 0, 1);
	validate_tree(
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0),
				NODE("e", HTTP_SUCCESS, 0)),
			NODE("x.y.z", 0, 0,
				NODE("e", HTTP_SUCCESS, 0))));

	cache_teardown();
}
END_TEST

START_TEST(test_cache_download_https_error)
{
	ck_assert_int_eq(0, system("rm -rf tmp/"));

	cache_prepare();

	dl_error = false;
	download_https("https://a.b.c/d", 0, 1);
	dl_error = true;
	download_https("https://a.b.c/e", -EINVAL, 1);
	validate_trees(
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
	validate_trees(
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0),
				NODE("e", CNF_DIRECT, -EINVAL))),
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0))));

	dl_error = false;
	download_https("https://a.b.c/e", -EINVAL, 0);
	validate_trees(
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0),
				NODE("e", CNF_DIRECT, -EINVAL))),
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0))));

	cache_teardown();
}
END_TEST

START_TEST(test_cache_cleanup_https)
{
	ck_assert_int_eq(0, system("rm -rf tmp/"));
	dl_error = false;

	/* First iteration; make a tree and clean it */
	__cache_prepare();
	download_https("https://a.b.c/d", 0, 1);
	download_https("https://a.b.c/e", 0, 1);
	cache_cleanup();
	validate_tree(
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0),
				NODE("e", HTTP_SUCCESS, 0))));

	/* Remove one branch */
	__cache_prepare();
	download_https("https://a.b.c/d", 0, 1);
	cache_cleanup();
	validate_tree(
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0))));

	/* Change the one branch */
	__cache_prepare();
	download_https("https://a.b.c/e", 0, 1);
	cache_cleanup();
	validate_tree(
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("e", HTTP_SUCCESS, 0))));

	/*
	 * Add a child to the same branch, do not update the old one
	 */
	__cache_prepare();
	download_https("https://a.b.c/e/f/g", 0, 1);
	cache_cleanup();
	validate_tree(
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("e", 0, 0,
					NODE("f", 0, 0,
						NODE("g", HTTP_SUCCESS, 0))))));

	/*
	 * Download parent, do not update child.
	 * Children need to die, because parent is now a file.
	 */
	__cache_prepare();
	download_https("https://a.b.c/e/f", 0, 1);
	cache_cleanup();
	validate_tree(
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("e", 0, 0,
					NODE("f", HTTP_SUCCESS, 0)))));

	/* Do it again. */
	__cache_prepare();
	download_https("https://a.b.c/e", 0, 1);
	cache_cleanup();
	validate_tree(
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("e", HTTP_SUCCESS, 0))));

	/* Empty the tree */
	__cache_prepare();
	cache_cleanup();
	validate_tree(NODE("https", 0, 0));

	/* Node exists, but file doesn't */
	__cache_prepare();
	download_https("https://a.b.c/e", 0, 1);
	download_https("https://a.b.c/f/g/h", 0, 1);
	validate_tree(
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("e", HTTP_SUCCESS, 0),
				NODE("f", 0, 0,
					NODE("g", 0, 0,
						NODE("h", HTTP_SUCCESS, 0))))));
	ck_assert_int_eq(0, system("rm -rf tmp/https/a.b.c/f/g"));
	cache_cleanup();
	validate_tree(
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("e", HTTP_SUCCESS, 0))));

	cache_teardown();
}
END_TEST

START_TEST(test_cache_cleanup_https_error)
{
	ck_assert_int_eq(0, system("rm -rf tmp/"));

	cache_prepare();

	/* Set up */
	dl_error = false;
	download_https("https://a.b.c/d", 0, 1);
	dl_error = true;
	download_https("https://a.b.c/e", -EINVAL, 1);
	validate_trees(
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0),
				NODE("e", CNF_DIRECT, -EINVAL))),
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0))));

	/* Deleted because file ENOENT. */
	cache_cleanup();
	validate_tree(
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0))));

	/* Fail d */
	__cache_prepare();
	dl_error = true;
	download_https("https://a.b.c/d", -EINVAL, 1);
	validate_trees(
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", CNF_DIRECT, -EINVAL))),
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0))));

	/* Clean up d because of error */
	cache_cleanup();
	validate_tree(NODE("https", 0, 0));

	cache_teardown();
}
END_TEST

START_TEST(test_dots)
{
	ck_assert_int_eq(0, system("rm -rf tmp/"));
	dl_error = false;

	cache_prepare();

	download_https("https://a.b.c/d", 0, 1);
	validate_tree(
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0))));

	download_https("https://a.b.c/d/.", 0, 0);
	validate_tree(
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("d", HTTP_SUCCESS, 0))));

	download_https("https://a.b.c/d/..", 0, 1);
	validate_tree(
		NODE("https", 0, 0,
			NODE("a.b.c", HTTP_SUCCESS, 0)));

	download_https("https://a.b.c/./d/../e", 0, 1);
	validate_tree(
		NODE("https", 0, 0,
			NODE("a.b.c", 0, 0,
				NODE("e", HTTP_SUCCESS, 0))));

	cache_teardown();
}
END_TEST

START_TEST(test_metadata_json)
{
	const time_t NOW = 1693952610;
	json_t *json;
	char *str;

	rsync = TNODE("rsync", 0, NOW + 0, NOW + 1, 0,
			TNODE("a.b.c", 0, NOW + 2, NOW + 3, 0,
				TNODE("d", SUCCESS, NOW + 4, NOW + 5, 0),
				TNODE("e", SUCCESS, NOW + 6, NOW + 7, 0)),
			TNODE("x.y.z", 0, NOW + 8, NOW + 9, 0,
				TNODE("w", SUCCESS, NOW + 0, NOW + 1, 0)));
	https = TNODE("https", 0, NOW + 2, NOW + 3, 0,
			TNODE("a", 0, NOW + 4, NOW + 5, 0,
				TNODE("b", HTTP_SUCCESS, NOW + 6, NOW + 7, 0),
				TNODE("c", HTTP_SUCCESS, NOW + 8, NOW + 9, 0)));

	json = build_metadata_json();
	ck_assert_int_eq(0, json_dump_file(json, "tmp/metadata.json", JSON_COMPACT));

	str = json_dumps(json, /* JSON_INDENT(4) */ JSON_COMPACT);
	/* printf("%s\n", str); */
	json_decref(json);

	ck_assert_str_eq(
		"[{\"basename\":\"rsync\",\"flags\":0,\"ts_success\":\"2023-09-05T16:23:30-0600\",\"ts_attempt\":\"2023-09-05T16:23:31-0600\",\"error\":0,\"children\":["
			"{\"basename\":\"a.b.c\",\"flags\":0,\"ts_success\":\"2023-09-05T16:23:32-0600\",\"ts_attempt\":\"2023-09-05T16:23:33-0600\",\"error\":0,\"children\":["
				"{\"basename\":\"d\",\"flags\":3,\"ts_success\":\"2023-09-05T16:23:34-0600\",\"ts_attempt\":\"2023-09-05T16:23:35-0600\",\"error\":0},"
				"{\"basename\":\"e\",\"flags\":3,\"ts_success\":\"2023-09-05T16:23:36-0600\",\"ts_attempt\":\"2023-09-05T16:23:37-0600\",\"error\":0}]},"
			"{\"basename\":\"x.y.z\",\"flags\":0,\"ts_success\":\"2023-09-05T16:23:38-0600\",\"ts_attempt\":\"2023-09-05T16:23:39-0600\",\"error\":0,\"children\":["
				"{\"basename\":\"w\",\"flags\":3,\"ts_success\":\"2023-09-05T16:23:30-0600\",\"ts_attempt\":\"2023-09-05T16:23:31-0600\",\"error\":0}]}]},"
		"{\"basename\":\"https\",\"flags\":0,\"ts_success\":\"2023-09-05T16:23:32-0600\",\"ts_attempt\":\"2023-09-05T16:23:33-0600\",\"error\":0,\"children\":["
			"{\"basename\":\"a\",\"flags\":0,\"ts_success\":\"2023-09-05T16:23:34-0600\",\"ts_attempt\":\"2023-09-05T16:23:35-0600\",\"error\":0,\"children\":["
				"{\"basename\":\"b\",\"flags\":11,\"ts_success\":\"2023-09-05T16:23:36-0600\",\"ts_attempt\":\"2023-09-05T16:23:37-0600\",\"error\":0},"
				"{\"basename\":\"c\",\"flags\":11,\"ts_success\":\"2023-09-05T16:23:38-0600\",\"ts_attempt\":\"2023-09-05T16:23:39-0600\",\"error\":0}]}]}]",
		str);
	free(str);

	cache_teardown();
	rsync = https = NULL;

	load_metadata_json();
	validate_trees(
		TNODE("rsync", 0, NOW + 0, NOW + 1, 0,
			TNODE("a.b.c", 0, NOW + 2, NOW + 3, 0,
				TNODE("d", SUCCESS, NOW + 4, NOW + 5, 0),
				TNODE("e", SUCCESS, NOW + 6, NOW + 7, 0)),
			TNODE("x.y.z", 0, NOW + 8, NOW + 9, 0,
				TNODE("w", SUCCESS, NOW + 0, NOW + 1, 0))),
		NULL);
	validate_trees(
		TNODE("https", 0, NOW + 2, NOW + 3, 0,
			TNODE("a", 0, NOW + 4, NOW + 5, 0,
				TNODE("b", HTTP_SUCCESS, NOW + 6, NOW + 7, 0),
				TNODE("c", HTTP_SUCCESS, NOW + 8, NOW + 9, 0))),
		NULL);
}
END_TEST

/* Boilerplate */

Suite *thread_pool_suite(void)
{
	Suite *suite;
	TCase *rsync , *https, *dot, *meta;

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
	tcase_add_test(https, test_dots);

	meta = tcase_create("metadata.json");
	tcase_add_test(https, test_metadata_json);

	suite = suite_create("local-cache");
	suite_add_tcase(suite, rsync);
	suite_add_tcase(suite, https);
	suite_add_tcase(suite, dot);
	suite_add_tcase(suite, meta);

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
