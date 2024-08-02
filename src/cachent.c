#include "cachent.h"

#include "alloc.h"
#include "config.h"
#include "log.h"
#include "types/array.h"
#include "types/path.h"
#include "types/url.h"

static struct cache_node *
cachent_root(char const *schema, char const *dir)
{
	struct cache_node *root;

	root = pzalloc(sizeof(struct cache_node));
	root->url = (char *)schema;
	root->path = join_paths(config_get_local_repository(), dir);
	root->name = strrchr(root->path, '/') + 1;
	root->flags = CNF_FREE_PATH;

	return root;
}

struct cache_node *
cachent_root_rsync(void)
{
	return cachent_root("rsync://", "rsync");
}

struct cache_node *
cachent_root_https(void)
{
	return cachent_root("https://", "https");
}

/* Preorder. @cb returns whether the children should be traversed. */
void
cachent_traverse(struct cache_node *root, bool (*cb)(struct cache_node *))
{
	struct cache_node *iter_start;
	struct cache_node *parent, *child;
	struct cache_node *tmp;

	if (!root)
		return;

	if (!cb(root))
		return;

	parent = root;
	iter_start = parent->children;
	if (iter_start == NULL)
		return;

reloop:	/* iter_start must not be NULL */
	HASH_ITER(hh, iter_start, child, tmp) {
		if (cb(child) && (child->children != NULL)) {
			parent = child;
			iter_start = parent->children;
			goto reloop;
		}
	}

	parent = iter_start->parent;
	do {
		if (parent == NULL)
			return;
		iter_start = parent->hh.next;
		parent = parent->parent;
	} while (iter_start == NULL);

	goto reloop;
}

static struct cache_node *
find_child(struct cache_node *parent, char const *name, size_t namelen)
{
	struct cache_node *child;
	HASH_FIND(hh, parent->children, name, namelen, child);
	return child;
}

/*
 * Returns perfect match or NULL. @msm will point to the Most Specific Match.
 * Assumes @path is normalized.
 * XXX if root doesn't match path, will return garbage
 */
struct cache_node *
cachent_find(struct cache_node *root, char const *path, struct cache_node **msm)
{
	struct tokenizer tkn;
	struct cache_node *parent;
	struct cache_node *child;

	token_init(&tkn, path);

	if (!token_next(&tkn) || strncmp(root->name, tkn.str, tkn.len) != 0) {
		*msm = NULL;
		return NULL;
	}

	for (parent = child = root; token_next(&tkn); parent = child) {
		child = find_child(parent, tkn.str, tkn.len);
		if (!child) {
			*msm = parent;
			return NULL;
		}
	}

	*msm = parent;
	return child;
}

static char *
inherit_path(char const *parent, char const *name, size_t nlen)
{
	char *child;
	size_t clen;

	clen = strlen(parent) + nlen + 2;
	child = pmalloc(clen);
	if (snprintf(child, clen, "%s/%.*s", parent, (int)nlen, name) >= clen)
		pr_crit("aaaaaa"); // XXX

	return child;
}

/* Get or create parent's child. */
static struct cache_node *
provide(struct cache_node *parent, char const *url,
    char const *name, size_t namelen)
{
	struct cache_node *child;

	child = find_child(parent, name, namelen);
	if (child != NULL)
		return child;

	child = pzalloc(sizeof(struct cache_node));
	child->url = pstrndup(url, name - url + namelen);
	child->path = inherit_path(parent->path, name, namelen);
	child->name = child->url + (name - url);
	child->flags = CNF_FREE_URL | CNF_FREE_PATH;
	if ((parent->flags & RSYNC_INHERIT) == RSYNC_INHERIT)
		child->flags |= RSYNC_INHERIT;
	if (parent->tmppath && !(parent->flags & CNF_RSYNC)) {
		child->tmppath = inherit_path(parent->tmppath, name, namelen);
		child->flags |= CNF_FREE_TMPPATH;
	}
	child->parent = parent;
	HASH_ADD_KEYPTR(hh, parent->children, child->name, namelen, child);

	return child;
}

/*
 * Get or create ancestor's descendant.
 *
 * Suppose @url is "rsync://a.b.c/d/e/f.cer": @ancestor has to be either
 * "rsync:", "rsync://a.b.c", "rsync://a.b.c/d", "rsync://a.b.c/d/e" or
 * "rsync://a.b.c/d/e/f.cer".
 *
 * Returns NULL if @ancestor doesn't match @url.
 *
 * The point of @ancestor is caging. @url will not be allowed to point to
 * anything that is not @ancestor or one of its descendants. (ie. dot-dotting is
 * allowed, but the end result must not land outside of @ancestor.)
 *
 * XXX In the end, it seems this is only being used by root ancestors.
 * Should probably separate the caging to a simple get.
 */
struct cache_node *
cachent_provide(struct cache_node *ancestor, char const *url)
{
	char *normal;
	array_index i;
	struct tokenizer tkn;

	normal = url_normalize(url);
	if (!normal)
		return NULL;

	for (i = 0; ancestor->url[i] != 0; i++)
		if (ancestor->url[i] != normal[i])
			goto fail;
	if (i != RPKI_SCHEMA_LEN && normal[i] != '/' && normal[i] != '\0')
		goto fail;

	token_init(&tkn, normal + i);
	while (token_next(&tkn))
		ancestor = provide(ancestor, normal, tkn.str, tkn.len);
	free(normal);
	return ancestor;

fail:	free(normal);
	return NULL;
}

#ifdef UNIT_TESTING
static void __delete_node_cb(struct cache_node const *);
#endif

static int
__delete_node(struct cache_node *node)
{
	int valid = node->flags & CNF_VALID;

#ifdef UNIT_TESTING
	__delete_node_cb(node);
#endif

	if (node->parent != NULL)
		HASH_DEL(node->parent->children, node);
	if (node->flags & CNF_FREE_URL)
		free(node->url);
	if (node->flags & CNF_FREE_PATH)
		free(node->path);
	if (node->flags & CNF_FREE_TMPPATH)
		free(node->tmppath);
	free(node);

	return valid;
}

int
cachent_delete(struct cache_node *node)
{
	struct cache_node *parent;
	int valid;

	if (!node)
		return 0;

	valid = node->flags & CNF_VALID;

	parent = node->parent;
	if (parent != NULL) {
		HASH_DEL(parent->children, node);
		node->parent = NULL;
	}

	do {
		while (node->children)
			node = node->children;

		parent = node->parent;
		valid |= __delete_node(node);
		node = parent;
	} while (node != NULL);

	return valid;
}

static void
print_node(struct cache_node *node, unsigned int tabs)
{
	unsigned int i;
	struct cache_node *child, *tmp;

	for (i = 0; i < tabs; i++)
		printf("\t");

	printf("%s -- ", node->name);
	printf("%s", (node->flags & CNF_RSYNC) ? "rsync " : "");
	printf("%s", (node->flags & CNF_CACHED) ? "cached " : "");
	printf("%s", (node->flags & CNF_FRESH) ? "fresh " : "");
	printf("%s", (node->flags & CNF_TOUCHED) ? "touched " : "");
	printf("%s", (node->flags & CNF_VALID) ? "valid " : "");
	printf("%s", (node->flags & CNF_NOTIFICATION) ? "notification " : "");
	printf("%s", (node->flags & CNF_WITHDRAWN) ? "withdrawn " : "");
	printf(" -- %s", node->tmppath);

	printf("\n");
	HASH_ITER(hh, node->children, child, tmp)
		print_node(child, tabs + 1);
}

void
cachent_print(struct cache_node *node)
{
	if (node)
		print_node(node, 0);
}