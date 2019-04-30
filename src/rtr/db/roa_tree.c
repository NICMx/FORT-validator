#include "rtr/db/roa_tree.h"

#include "common.h"
#include "data_structure/array_list.h"
#include "data_structure/circular_indexer.h"
#include "rtr/db/roa.h"

DEFINE_ARRAY_LIST_STRUCT(nodes, struct node);

struct node {
	struct rfc5280_name *subject_name;
	struct node *parent;
	/*
	 * BTW: There's nothing in this code stopping both children and roa from
	 * being not null, but it should never happen naturally.
	 */
	struct nodes children;
	struct roa *roa;
};

struct roa_tree {
	struct node *root;
	struct node *current;
	unsigned int references;
};

DEFINE_ARRAY_LIST_FUNCTIONS(nodes, struct node)

static void
node_init(struct node *node, struct rfc5280_name *subject_name,
    struct node *parent)
{
	node->subject_name = subject_name;
	x509_name_get(subject_name);
	node->parent = parent;
	nodes_init(&node->children);
	node->roa = NULL;
}

static struct node *
node_create(struct rfc5280_name *subject_name, struct node *parent)
{
	struct node *node;

	node = malloc(sizeof(struct node));
	if (node == NULL)
		return NULL;

	node_init(node, subject_name, parent);
	return node;
}

static void
node_cleanup(struct node *node)
{
	if (node->subject_name != NULL)
		x509_name_put(node->subject_name);
	nodes_cleanup(&node->children, node_cleanup);
	if (node->roa != NULL)
		roa_destroy(node->roa);
}

static int
node_add_child(struct node *parent, struct rfc5280_name *subject_name)
{
	struct node child;
	int error;

	node_init(&child, subject_name, parent);

	error = nodes_add(&parent->children, &child);
	if (error)
		node_cleanup(&child);

	return error;
}

/**
 * Performs lazy initialization if the root does not exist.
 */
static struct node *
get_root(struct roa_tree *tree, struct rfc5280_name *subject_name)
{
	if (tree->root == NULL)
		tree->root = node_create(subject_name, NULL);
	return tree->root;
}

struct roa_tree *
roa_tree_create(void)
{
	struct roa_tree *tree;

	tree = malloc(sizeof(struct roa_tree));
	if (tree == NULL)
		return NULL;

	tree->root = NULL;
	tree->current = NULL;
	tree->references = 1;
	return tree;
}

static void
roa_tree_cleanup(struct roa_tree *tree)
{
	if (tree->root != NULL) {
		node_cleanup(tree->root);
		free(tree->root);
		tree->root = NULL;
	}
	tree->current = NULL;
}

void
roa_tree_get(struct roa_tree *tree)
{
	tree->references++;
}

void
roa_tree_put(struct roa_tree *tree)
{
	tree->references--;
	if (tree->references == 0) {
		roa_tree_cleanup(tree);
		free(tree);
	}
}

static int
__foreach_v4(struct roa *roa, vrp_foreach_cb cb, void *arg)
{
	struct v4_address *addr;
	struct vrp vrp;
	int error;

	vrp.asn = roa->as;
	vrp.addr_fam = AF_INET;
	vrp.flags = FLAG_ANNOUNCEMENT;

	ARRAYLIST_FOREACH(&roa->addrs4, addr) {
		vrp.prefix.v4 = addr->prefix.addr;
		vrp.prefix_length = addr->prefix.len;
		vrp.max_prefix_length = addr->max_length;
		error = cb(&vrp, arg);
		if (error)
			return error;
	}

	return 0;
}

static int
__foreach_v6(struct roa *roa, vrp_foreach_cb cb, void *arg)
{
	struct v6_address *addr;
	struct vrp vrp;
	int error;

	vrp.asn = roa->as;
	vrp.addr_fam = AF_INET6;
	vrp.flags = FLAG_ANNOUNCEMENT;

	ARRAYLIST_FOREACH(&roa->addrs6, addr) {
		vrp.prefix.v6 = addr->prefix.addr;
		vrp.prefix_length = addr->prefix.len;
		vrp.max_prefix_length = addr->max_length;
		error = cb(&vrp, arg);
		if (error)
			return error;
	}

	return 0;
}

int
__foreach(struct node *node, vrp_foreach_cb cb, void *arg)
{
	struct node *child;
	int error;

	ARRAYLIST_FOREACH(&node->children, child) {
		error = __foreach(child, cb, arg);
		if (error)
			return error;
	}

	if (node->roa != NULL) {
		error = __foreach_v4(node->roa, cb, arg);
		if (error)
			return error;
		error = __foreach_v6(node->roa, cb, arg);
		if (error)
			return error;
	}

	return 0;
}

int
roa_tree_foreach_roa(struct roa_tree *tree, vrp_foreach_cb cb, void *arg)
{
	return (tree->root != NULL) ? __foreach(tree->root, cb, arg) : 0;
}

int
forthandler_reset(struct roa_tree *tree)
{
	roa_tree_cleanup(tree);
	return 0;
}

struct node *
get_last_node(struct nodes *nodes)
{
	if (nodes->array == NULL || nodes->len == 0)
		return NULL;

	return &nodes->array[nodes->len - 1];
}

int
forthandler_go_down(struct roa_tree *tree,
    struct rfc5280_name *subject_name)
{
	int error;
	if (tree->current != NULL) {
		error = node_add_child(tree->current, subject_name);
		if (error)
			return error;
		tree->current = get_last_node(&tree->current->children);
		return 0;
	}

	tree->current = get_root(tree, subject_name);
	return (tree->current != NULL) ? 0 : pr_enomem();
}

int
forthandler_go_up(struct roa_tree *tree)
{
	if (tree->current != NULL)
		tree->current = tree->current->parent;
	return 0;
}

static int
get_current_roa(struct roa_tree *tree, uint32_t asn, struct roa **result)
{
	struct roa *roa;
	int error;

	if (tree->current == NULL)
		return pr_crit("Validator posted ROA during incorrect context.");

	roa = tree->current->roa;
	if (roa == NULL) {
		error = roa_create(asn, &roa);
		if (error)
			return error;
		tree->current->roa = roa;
	}

	*result = roa;
	return 0;
}

int
forthandler_handle_roa_v4(struct roa_tree *tree, uint32_t asn,
    struct ipv4_prefix const *prefix4, uint8_t max_length)
{
	struct roa *roa;
	int error;
	error = get_current_roa(tree, asn, &roa);
	return error ? error : roa_add_v4(roa, asn, prefix4, max_length);
}

int
forthandler_handle_roa_v6(struct roa_tree *tree, uint32_t asn,
    struct ipv6_prefix const *prefix6, uint8_t max_length)
{
	struct roa *roa;
	int error;
	error = get_current_roa(tree, asn, &roa);
	return error ? error : roa_add_v6(roa, asn, prefix6, max_length);
}

static bool
find_subject_name(struct circular_indexer *indexer,
    struct rfc5280_name *subject_name, struct node *c2array,
    array_index *result)
{
	array_index *i;

	ARRIDX_FOREACH(indexer, i) {
		if (x509_name_equals(subject_name, c2array[*i].subject_name)) {
			*result = *i;
			return true;
		}
	}

	return false;
}

static int
add_all_roas_v4(struct deltas *deltas, struct roa *roa, enum delta_op op)
{
	struct v4_address *addr;
	int error;

	ARRAYLIST_FOREACH(&roa->addrs4, addr) {
		error = deltas_add_roa_v4(deltas, roa->as, addr, op);
		if (error)
			return error;
	}

	return 0;
}

static int
add_all_roas_v6(struct deltas *deltas, struct roa *roa, enum delta_op op)
{
	struct v6_address *addr;
	int error;

	ARRAYLIST_FOREACH(&roa->addrs6, addr) {
		error = deltas_add_roa_v6(deltas, roa->as, addr, op);
		if (error)
			return error;
	}

	return 0;
}

static int
add_all_deltas(struct node *node, struct deltas *deltas, enum delta_op op)
{
	struct node *child;
	int error;

	ARRAYLIST_FOREACH(&node->children, child) {
		error = add_all_deltas(child, deltas, op);
		if (error)
			return error;
	}

	if (child->roa != NULL) {
		error = add_all_roas_v4(deltas, child->roa, op);
		if (error)
			return error;
		error = add_all_roas_v6(deltas, child->roa, op);
		if (error)
			return error;
	}

	return 0;
}

static int compute_deltas_node(struct node *, struct node *, struct deltas *);

static int
handle_delta_children(struct nodes *children1, struct nodes *children2,
    struct deltas *deltas)
{
	/*
	 * Most of the time, the arrays will be identical.
	 * When they are not, most of the time the arrays will be mostly
	 * identical.
	 *
	 * We will try our hardest to traverse the arrays as sequentially as
	 * possible to exploit these facts.
	 *
	 * Notice that this is the same algorithm as HANDLE_ROAS_FN().
	 * Changes to one function might need to cascade to the other.
	 */

	struct node *c1node;

	struct node *c2array;
	array_index c2; /* counter for c2array */
	array_index *c2p; /* counter for c2array, pointer */

	struct circular_indexer c2indexer;

	int error = 0;

	c2array = children2->array;
	arridx_init(&c2indexer, children2->len);

	ARRAYLIST_FOREACH(children1, c1node) {
		if (find_subject_name(&c2indexer, c1node->subject_name,
		    c2array, &c2)) {
			error = compute_deltas_node(c1node, &c2array[c2],
			    deltas);
			if (error)
				goto end;

			error = arridx_remove(&c2indexer);
		} else {
			error = add_all_deltas(c1node, deltas, DELTA_RM);
		}
		if (error)
			goto end;
	}

	ARRIDX_FOREACH(&c2indexer, c2p) {
		error = add_all_deltas(&c2array[*c2p], deltas, DELTA_ADD);
		if (error)
			goto end;
	}

end:	arridx_cleanup(&c2indexer);
	return error;
}

static bool
find_addr_v4(struct v4_address *address, struct v4_addresses *array,
    struct circular_indexer *indexer)
{
	array_index *i;

	ARRIDX_FOREACH(indexer, i)
		if (prefix4_equals(&address->prefix, &array->array[*i].prefix))
			return true;

	return false;
}

static bool
find_addr_v6(struct v6_address *address, struct v6_addresses *array,
    struct circular_indexer *indexer)
{
	array_index *i;

	ARRIDX_FOREACH(indexer, i)
		if (prefix6_equals(&address->prefix, &array->array[*i].prefix))
			return true;

	return false;
}

#define HANDLE_ROAS_FN(name, array_type, node_type, field, find_fn,	\
    add_one_fn, add_all_fn)						\
	static int							\
	name(struct roa *roa1, struct roa *roa2, struct deltas *deltas)	\
	{								\
		/* Notice that this is the same algorithm as */		\
		/* handle_delta_children(). Changes to one function */	\
		/* might need to cascade to the other. */		\
									\
		struct array_type *addrs1;				\
		struct node_type *a1; /* address cursor for addrs1 */	\
									\
		struct array_type *addrs2;				\
		array_index *a2p; /* counter for addrs2, pointer */	\
									\
		struct circular_indexer r2indexer;			\
		int error = 0;						\
									\
		if (roa1->as != roa2->as) {				\
			error = add_all_fn(deltas, roa1, DELTA_RM);	\
			if (error)					\
				return error;				\
			return add_all_fn(deltas, roa2, DELTA_ADD);	\
		}							\
									\
		addrs1 = &roa1->field;					\
		addrs2 = &roa2->field;					\
		arridx_init(&r2indexer, addrs2->len);			\
									\
		ARRAYLIST_FOREACH(addrs1, a1) {				\
			if (find_fn(a1, addrs2, &r2indexer))		\
				error = arridx_remove(&r2indexer);	\
			else						\
				error = add_one_fn(deltas,		\
				    roa1->as, a1, DELTA_RM);		\
			if (error)					\
				goto end;				\
		}							\
									\
		ARRIDX_FOREACH(&r2indexer, a2p) {			\
			error = add_one_fn(deltas, roa2->as,		\
			    &addrs2->array[*a2p], DELTA_ADD);		\
			if (error)					\
				goto end;				\
		}							\
									\
	end:	arridx_cleanup(&r2indexer);				\
		return error;						\
	}

HANDLE_ROAS_FN(handle_roas_v4, v4_addresses, v4_address, addrs4, find_addr_v4,
    deltas_add_roa_v4, add_all_roas_v4)
HANDLE_ROAS_FN(handle_roas_v6, v6_addresses, v6_address, addrs6, find_addr_v6,
    deltas_add_roa_v6, add_all_roas_v6)

static int
compute_deltas_node(struct node *n1, struct node *n2, struct deltas *deltas)
{
	int error;

	error = handle_delta_children(&n1->children, &n2->children, deltas);
	if (error)
		return error;

	/** TODO I still need to validate that this is ok */
	if (n1->roa == NULL || n2->roa == NULL)
		return 0;

	error = handle_roas_v4(n1->roa, n2->roa, deltas);
	if (error)
		return error;

	return handle_roas_v6(n1->roa, n2->roa, deltas);
}

int
compute_deltas(struct roa_tree *t1, struct roa_tree *t2, struct deltas **result)
{
	struct deltas *deltas;
	int error;

	assert(t1->root != NULL);
	assert(t2->root != NULL);

	error = deltas_create(&deltas);
	if (error)
		return error;

	error = compute_deltas_node(t1->root, t2->root, deltas);
	if (error) {
		deltas_destroy(deltas);
		return error;
	}

	*result = deltas;
	return 0;
}
