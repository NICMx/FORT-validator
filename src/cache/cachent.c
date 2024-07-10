#include "cache/cachent.h"

#include "alloc.h"
#include "config.h"
#include "data_structure/common.h"
#include "data_structure/path_builder.h"

/* @schema must contain a colon suffix, otherwise lookups won't work */
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

static char *
path_rewind(char const *root, char *cursor)
{
	for (cursor -= 2; root <= cursor; cursor--)
		if (*cursor == '/')
			return cursor + 1;
	return NULL;
}

/* Collapses '//' (after the schema), '.' and '..'. */
static char *
normalize(char const *url)
{
	char *normal, *dst, *root;
	struct tokenizer tkn;

	if (strncmp(url, "rsync://", RPKI_SCHEMA_LEN) &&
	    strncmp(url, "https://", RPKI_SCHEMA_LEN))
		return NULL;

	normal = pstrdup(url);
	dst = normal + RPKI_SCHEMA_LEN;
	root = dst - 1;
	token_init(&tkn, url + RPKI_SCHEMA_LEN);

	while (token_next(&tkn)) {
		if (tkn.len == 1 && tkn.str[0] == '.')
			continue;
		if (tkn.len == 2 && tkn.str[0] == '.' && tkn.str[1] == '.') {
			dst = path_rewind(root, dst);
			if (!dst)
				goto fail;
			continue;
		}
		strncpy(dst, tkn.str, tkn.len);
		dst[tkn.len] = '/';
		dst += tkn.len + 1;
	}

	/* Reject URL if there's nothing after the schema. Maybe unnecessary. */
	if (dst == normal + RPKI_SCHEMA_LEN)
		goto fail;

	dst[-1] = '\0';
	return normal;

fail:	free(normal);
	return NULL;
}

/* Get or create parent's child. */
static struct cache_node *
provide(struct cache_node *parent, char const *url,
    char const *name, size_t namelen)
{
	struct cache_node *child;

	HASH_FIND(hh, parent->children, name, namelen, child);
	if (child != NULL)
		return child;

	child = pzalloc(sizeof(struct cache_node));
	child->url = pstrndup(url, name - url + namelen);
	child->name = child->url + (name - url);
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

	normal = normalize(url);
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

	printf("%s ", node->name);
	printf("%s", (node->flags & CNF_RSYNC) ? "RSYNC " : "");
	printf("%s", (node->flags & CNF_FRESH) ? "Fresh " : "");
	printf("%s", (node->flags & CNF_TOUCHED) ? "Touched " : "");
	printf("%s", (node->flags & CNF_VALID) ? "Valid " : "");
	printf("%s\n", (node->flags & CNF_WITHDRAWN) ? "Withdrawn " : "");

	HASH_ITER(hh, node->children, child, tmp)
		print_node(child, tabs + 1);
}

void
cachent_print(struct cache_node *node)
{
	print_node(node, 0);
}
