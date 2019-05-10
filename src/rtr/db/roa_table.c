#include "rtr/db/roa_table.h"

#include "data_structure/uthash.h"

struct hashable_roa {
	/*
	 * TODO (whatever) flags is not useful here.
	 * Maybe separate struct vrp into two structures: One that doesn't
	 * contain flags, and one that contains the other.
	 */
	struct vrp data;
	UT_hash_handle hh;
};

struct roa_table {
	struct hashable_roa *roas;
};

struct roa_table *
roa_table_create(void)
{
	struct roa_table *table;

	table = malloc(sizeof(struct roa_table));
	if (table == NULL)
		return NULL;

	table->roas = NULL;
	return table;
}

static void
roa_table_cleanup(struct roa_table *table)
{
	struct hashable_roa *node;
	struct hashable_roa *tmp;

	HASH_ITER(hh, table->roas, node, tmp) {
		HASH_DEL(table->roas, node);
		free(node);
	}
}

void
roa_table_destroy(struct roa_table *table)
{
	roa_table_cleanup(table);
	free(table);
}

int
roa_table_foreach_roa(struct roa_table *table, vrp_foreach_cb cb, void *arg)
{
	struct hashable_roa *node, *tmp;
	int error;

	HASH_ITER(hh, table->roas, node, tmp) {
		error = cb(&node->data, arg);
		if (error)
			return error;
	}

	return 0;
}

int
rtrhandler_reset(struct roa_table *table)
{
	roa_table_cleanup(table);
	return 0;
}

static struct hashable_roa *
create_roa(uint32_t asn, uint8_t max_length)
{
	struct hashable_roa *roa;

	roa = malloc(sizeof(struct hashable_roa));
	if (roa == NULL)
		return NULL;
	/* Needed by uthash */
	memset(roa, 0, sizeof(struct hashable_roa));

	roa->data.asn = asn;
	roa->data.max_prefix_length = max_length;
	roa->data.flags = FLAG_ANNOUNCEMENT;

	return roa;
}

static int
add_roa(struct roa_table *table, struct hashable_roa *new)
{
	struct hashable_roa *old;

	HASH_REPLACE(hh, table->roas, data, sizeof(new->data), new, old);
	if (old != NULL)
		free(old);

	return 0;
}

static int
duplicate_roa(struct roa_table *dst, struct hashable_roa *new)
{
	struct vrp vrp;
	struct ipv4_prefix prefix4;
	struct ipv6_prefix prefix6;

	vrp = new->data;
	switch (vrp.addr_fam) {
	case AF_INET:
		prefix4.addr = vrp.prefix.v4;
		prefix4.len = vrp.prefix_length;
		return rtrhandler_handle_roa_v4(dst, vrp.asn, &prefix4,
		    vrp.max_prefix_length);
	case AF_INET6:
		prefix6.addr = vrp.prefix.v6;
		prefix6.len = vrp.prefix_length;
		return rtrhandler_handle_roa_v6(dst, vrp.asn, &prefix6,
		    vrp.max_prefix_length);
	}
	return pr_crit("Unknown address family: %d", vrp.addr_fam);
}

static int
roa_table_merge(struct roa_table *dst, struct roa_table *src)
{
	struct hashable_roa *node, *tmp, *found;
	int error;

	/** Must look for it due to the new mem allocation */
	HASH_ITER(hh, src->roas, node, tmp) {
		HASH_FIND(hh, dst->roas, &node->data, sizeof(node->data),
		    found);
		if (found != NULL)
			continue;
		error = duplicate_roa(dst, node);
		if (error)
			return error;
	}

	return 0;
}

int
rtrhandler_merge(struct roa_table *dst, struct roa_table *src)
{
	return roa_table_merge(dst, src);
}

void
roa_table_remove_roa(struct roa_table *table, struct vrp *del)
{
	struct hashable_roa *ptr;

	HASH_FIND(hh, table->roas, del, sizeof(*del), ptr);
	if (ptr != NULL) {
		HASH_DELETE(hh, table->roas, ptr);
		free(ptr);
	}
}

int
rtrhandler_handle_roa_v4(struct roa_table *table, uint32_t asn,
    struct ipv4_prefix const *prefix4, uint8_t max_length)
{
	struct hashable_roa *roa;

	roa = create_roa(asn, max_length);
	if (roa == NULL)
		return pr_enomem();
	roa->data.prefix.v4 = prefix4->addr;
	roa->data.prefix_length = prefix4->len;
	roa->data.addr_fam = AF_INET;

	return add_roa(table, roa);
}

int
rtrhandler_handle_roa_v6(struct roa_table *table, uint32_t asn,
    struct ipv6_prefix const *prefix6, uint8_t max_length)
{
	struct hashable_roa *roa;

	roa = create_roa(asn, max_length);
	if (roa == NULL)
		return pr_enomem();
	roa->data.prefix.v6 = prefix6->addr;
	roa->data.prefix_length = prefix6->len;
	roa->data.addr_fam = AF_INET6;

	return add_roa(table, roa);
}

static int
add_delta(struct deltas *deltas, struct hashable_roa *roa, enum delta_op op)
{
	union {
		struct v4_address v4;
		struct v6_address v6;
	} addr;

	switch (roa->data.addr_fam) {
	case AF_INET:
		addr.v4.prefix.addr = roa->data.prefix.v4;
		addr.v4.prefix.len = roa->data.prefix_length;
		addr.v4.max_length = roa->data.max_prefix_length;
		return deltas_add_roa_v4(deltas, roa->data.asn, &addr.v4, op);
	case AF_INET6:
		addr.v6.prefix.addr = roa->data.prefix.v6;
		addr.v6.prefix.len = roa->data.prefix_length;
		addr.v6.max_length = roa->data.max_prefix_length;
		return deltas_add_roa_v6(deltas, roa->data.asn, &addr.v6, op);
	}

	return pr_crit("Unknown address family: %d", roa->data.addr_fam);
}

/*
 * Copies `@roas1 - roas2` into @deltas.
 *
 * (Places the ROAs that exist in @roas1 but not in @roas2 in @deltas.)
 */
static int
add_deltas(struct hashable_roa *roas1, struct hashable_roa *roas2,
    struct deltas *deltas, enum delta_op op)
{
	struct hashable_roa *n1; /* A node from @roas1 */
	struct hashable_roa *n2; /* A node from @roas2 */
	int error;

	for (n1 = roas1; n1 != NULL; n1 = n1->hh.next) {
		HASH_FIND(hh, roas2, &n1->data, sizeof(n1->data), n2);
		if (n2 == NULL) {
			error = add_delta(deltas, n1, op);
			if (error)
				return error;
		}
	}

	return 0;
}

int
compute_deltas(struct roa_table *old, struct roa_table *new,
    struct deltas **result)
{
	struct deltas *deltas;
	int error;

	error = deltas_create(&deltas);
	if (error)
		return error;

	error = add_deltas(new->roas, old->roas, deltas, DELTA_ADD);
	if (error)
		goto fail;
	error = add_deltas(old->roas, new->roas, deltas, DELTA_RM);
	if (error)
		goto fail;

	*result = deltas;
	return 0;

fail:
	deltas_destroy(deltas);
	return error;
}
