#include "cache/cachent.h"

#include "alloc.h"
#include "config.h"
#include "data_structure/common.h"
#include "data_structure/path_builder.h"
#include "types/url.h"

struct cache_node *
cachent_create_root(char const *schema)
{
	struct cache_node *root;

	root = pzalloc(sizeof(struct cache_node));
	root->url = pstrdup(schema);
	root->name = root->url;

	return root;
}

/* Preorder. @cb returns whether the children should be traversed. */
int
cachent_traverse(struct cache_node *root,
    bool (*cb)(struct cache_node *, char const *))
{
	struct cache_node *iter_start;
	struct cache_node *parent, *child;
	struct cache_node *tmp;
	struct path_builder pb;
	int error;

	if (!root)
		return 0;

	pb_init(&pb);

	error = pb_append(&pb, config_get_local_repository());
	if (error)
		goto end;

	error = pb_append(&pb, root->name);
	if (error)
		goto end;
	if (!cb(root, pb.string))
		goto end;

	parent = root;
	iter_start = parent->children;
	if (iter_start == NULL)
		goto end;

reloop:	/* iter_start must not be NULL */
	HASH_ITER(hh, iter_start, child, tmp) {
		error = pb_append(&pb, child->name);
		if (error)
			goto end;

		if (cb(child, pb.string) && (child->children != NULL)) {
			parent = child;
			iter_start = parent->children;
			goto reloop;
		}

		pb_pop(&pb, true);
	}

	parent = iter_start->parent;
	do {
		if (parent == NULL)
			goto end;
		pb_pop(&pb, true);
		iter_start = parent->hh.next;
		parent = parent->parent;
	} while (iter_start == NULL);

	goto reloop;

end:	pb_cleanup(&pb);
	return error;
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
	child->name = child->url + (name - url);
	if ((parent->flags & RSYNC_INHERIT) == RSYNC_INHERIT) {
		PR_DEBUG_MSG("parent %s has inherit; setting on %s.", parent->name, child->name);
		child->flags = RSYNC_INHERIT;
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
 * XXX review callers; can now return NULL.
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
	if (normal[i] != '/' && normal[i] != '\0')
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

static void
__delete_node(struct cache_node *node)
{
#ifdef UNIT_TESTING
	__delete_node_cb(node);
#endif

	if (node->parent != NULL)
		HASH_DEL(node->parent->children, node);
	free(node->url);
	free(node->tmpdir);
	free(node);
}

void
cachent_delete(struct cache_node *node)
{
	struct cache_node *parent;

	if (!node)
		return;

	parent = node->parent;
	if (parent != NULL) {
		HASH_DEL(parent->children, node);
		node->parent = NULL;
	}

	do {
		while (node->children)
			node = node->children;

		parent = node->parent;
		__delete_node(node);
		node = parent;
	} while (node != NULL);
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
	printf("%s", (node->flags & CNF_CHANGED) ? "changed " : "");
	printf("%s", (node->flags & CNF_TOUCHED) ? "touched " : "");
	printf("%s", (node->flags & CNF_VALID) ? "valid " : "");
	printf("%s", (node->flags & CNF_NOTIFICATION) ? "notification " : "");
	printf("%s", (node->flags & CNF_WITHDRAWN) ? "withdrawn " : "");
	printf(" -- %s", node->tmpdir);

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
