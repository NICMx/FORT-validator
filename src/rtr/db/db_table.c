#include "rtr/db/db_table.h"

#include <sys/types.h> /* AF_INET, AF_INET6 (needed in OpenBSD) */
#include <sys/socket.h> /* AF_INET, AF_INET6 (needed in OpenBSD) */
#include "data_structure/uthash_nonfatal.h"

struct hashable_roa {
	struct vrp data;
	UT_hash_handle hh;
};

struct hashable_key {
	struct router_key data;
	UT_hash_handle hh;
};

struct db_table {
	struct hashable_roa *roas;
	struct hashable_key *router_keys;
};

struct db_table *
db_table_create(void)
{
	struct db_table *table;

	table = malloc(sizeof(struct db_table));
	if (table == NULL)
		return NULL;

	table->roas = NULL;
	table->router_keys = NULL;
	return table;
}

void
db_table_destroy(struct db_table *table)
{
	struct hashable_roa *node;
	struct hashable_roa *tmp;
	struct hashable_key *node_key;
	struct hashable_key *tmp_key;

	HASH_ITER(hh, table->roas, node, tmp) {
		HASH_DEL(table->roas, node);
		free(node);
	}

	HASH_ITER(hh, table->router_keys, node_key, tmp_key) {
		HASH_DEL(table->router_keys, node_key);
		router_key_cleanup(&node_key->data);
		free(node_key);
	}

	free(table);
}

int
db_table_foreach_roa(struct db_table *table, vrp_foreach_cb cb, void *arg)
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
db_table_foreach_router_key(struct db_table *table, router_key_foreach_cb cb,
    void *arg)
{
	struct hashable_key *node, *tmp;
	int error;

	HASH_ITER(hh, table->router_keys, node, tmp) {
		error = cb(&node->data, arg);
		if (error)
			return error;
	}

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

	return roa;
}

static int
add_roa(struct db_table *table, struct hashable_roa *new)
{
	struct hashable_roa *old;

	errno = 0;
	HASH_REPLACE(hh, table->roas, data, sizeof(new->data), new, old);
	if (errno)
		return -pr_errno(errno, "ROA couldn't be added to hash table");
	if (old != NULL)
		free(old);

	return 0;
}

static int
add_router_key(struct db_table *table, struct hashable_key *new)
{
	struct hashable_key *old;

	errno = 0;
	HASH_REPLACE(hh, table->router_keys, data, sizeof(new->data), new, old);
	if (errno)
		return -pr_errno(errno, "Router Key couldn't be added to hash table");
	if (old != NULL) {
		router_key_cleanup(&old->data);
		free(old);
	}

	return 0;
}

static int
duplicate_roa(struct db_table *dst, struct hashable_roa *new)
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

	pr_crit("Unknown address family: %d", vrp.addr_fam);
}

static int
duplicate_key(struct db_table *dst, struct hashable_key *new)
{
	struct sk_info *sk = new->data.sk;

	return rtrhandler_handle_router_key(dst, sk_info_get_ski(sk),
	    new->data.as, sk_info_get_spk(sk));
}

#define MERGE_ITER(table_prop, name, err_var)				\
	struct hashable_##name *node_##name, *tmp_##name, *found_##name;\
	HASH_ITER(hh, src->table_prop, node_##name, tmp_##name) {	\
		HASH_FIND(hh, dst->table_prop, &node_##name->data,	\
			sizeof(node_##name->data), found_##name);	\
		if (found_##name != NULL)				\
			continue;					\
		err_var = duplicate_##name(dst, node_##name);		\
		if (err_var)						\
			return err_var;					\
	}

static int
db_table_merge(struct db_table *dst, struct db_table *src)
{
	int error;

	/** Must look for elements due to the new mem allocation */
	MERGE_ITER(roas, roa, error)
	MERGE_ITER(router_keys, key, error)

	return 0;
}

int
db_table_clone(struct db_table **dst, struct db_table *src)
{
	int error;

	*dst = db_table_create();
	if (*dst == NULL)
		return pr_enomem();

	error = db_table_merge(*dst, src);
	if (error)
		free(*dst);

	return error;
}

void
db_table_remove_roa(struct db_table *table, struct vrp const *del)
{
	struct hashable_roa *ptr;

	HASH_FIND(hh, table->roas, del, sizeof(*del), ptr);
	if (ptr != NULL) {
		HASH_DELETE(hh, table->roas, ptr);
		free(ptr);
	}
}

/*
 * FIXME and TODO: add more funcs for router keys
 * void
 * db_table_remove_router_key(struct db_table *table,
 *     struct router_key const *del)
 * {
 * 	struct hashable_key *ptr;
 *
 * 	HASH_FIND(hh, table->router_keys, del, sizeof(*del), ptr);
 * 	if (ptr != NULL) {
 * 		HASH_DELETE(hh, table->router_keys, ptr);
 * 		router_key_cleanup(&ptr->data);
 * 		free(ptr);
 * 	}
 * }
 */

int
rtrhandler_handle_roa_v4(struct db_table *table, uint32_t asn,
    struct ipv4_prefix const *prefix4, uint8_t max_length)
{
	struct hashable_roa *roa;
	int error;

	roa = create_roa(asn, max_length);
	if (roa == NULL)
		return pr_enomem();
	roa->data.prefix.v4 = prefix4->addr;
	roa->data.prefix_length = prefix4->len;
	roa->data.addr_fam = AF_INET;

	error = add_roa(table, roa);
	if (error)
		free(roa);
	return error;
}

int
rtrhandler_handle_roa_v6(struct db_table *table, uint32_t asn,
    struct ipv6_prefix const *prefix6, uint8_t max_length)
{
	struct hashable_roa *roa;
	int error;

	roa = create_roa(asn, max_length);
	if (roa == NULL)
		return pr_enomem();
	roa->data.prefix.v6 = prefix6->addr;
	roa->data.prefix_length = prefix6->len;
	roa->data.addr_fam = AF_INET6;

	error = add_roa(table, roa);
	if (error)
		free(roa);
	return error;
}

int
rtrhandler_handle_router_key(struct db_table *table,
    unsigned char const *ski, uint32_t as, unsigned char const *spk)
{
	struct hashable_key *key;
	int error;

	key = malloc(sizeof(struct hashable_key));
	if (key == NULL)
		return pr_enomem();
	/* Needed by uthash */
	memset(key, 0, sizeof(struct hashable_key));

	error = router_key_init(&key->data, ski, as, spk);
	if (error) {
		free(key);
		return error;
	}

	error = add_router_key(table, key);
	if (error) {
		router_key_cleanup(&key->data);
		free(key);
	}
	return error;
}

static int
add_roa_delta(struct deltas *deltas, struct hashable_roa *roa, int op)
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

	pr_crit("Unknown address family: %d", roa->data.addr_fam);
}

/*
 * Copies `@roas1 - roas2` into @deltas.
 *
 * (Places the ROAs that exist in @roas1 but not in @roas2 in @deltas.)
 */
static int
add_roa_deltas(struct hashable_roa *roas1, struct hashable_roa *roas2,
    struct deltas *deltas, int op)
{
	struct hashable_roa *n1; /* A node from @roas1 */
	struct hashable_roa *n2; /* A node from @roas2 */
	int error;

	for (n1 = roas1; n1 != NULL; n1 = n1->hh.next) {
		HASH_FIND(hh, roas2, &n1->data, sizeof(n1->data), n2);
		if (n2 == NULL) {
			error = add_roa_delta(deltas, n1, op);
			if (error)
				return error;
		}
	}

	return 0;
}

static int
add_router_key_delta(struct deltas *deltas, struct hashable_key *key, int op)
{
	return deltas_add_bgpsec(deltas, &key->data, op);
}

/*
 * Copies `@keys1 - keys2` into @deltas.
 *
 * (Places the Router Keys that exist in @keys1 but not in @key2 in @deltas.)
 */
static int
add_router_key_deltas(struct hashable_key *keys1, struct hashable_key *keys2,
    struct deltas *deltas, int op)
{
	struct hashable_key *n1; /* A node from @keys1 */
	struct hashable_key *n2; /* A node from @keys2 */
	int error;

	for (n1 = keys1; n1 != NULL; n1 = n1->hh.next) {
		HASH_FIND(hh, keys2, &n1->data, sizeof(n1->data), n2);
		if (n2 == NULL) {
			error = add_router_key_delta(deltas, n1, op);
			if (error)
				return error;
		}
	}

	return 0;
}

int
compute_deltas(struct db_table *old, struct db_table *new,
    struct deltas **result)
{
	struct deltas *deltas;
	int error;

	error = deltas_create(&deltas);
	if (error)
		return error;

	error = add_roa_deltas(new->roas, old->roas, deltas, FLAG_ANNOUNCEMENT);
	if (error)
		goto fail;
	error = add_roa_deltas(old->roas, new->roas, deltas, FLAG_WITHDRAWAL);
	if (error)
		goto fail;
	error = add_router_key_deltas(new->router_keys, old->router_keys,
	    deltas, FLAG_ANNOUNCEMENT);
	if (error)
		goto fail;
	error = add_router_key_deltas(old->router_keys, new->router_keys,
	    deltas, FLAG_WITHDRAWAL);
	if (error)
		goto fail;

	*result = deltas;
	return 0;

fail:
	deltas_refput(deltas);
	return error;
}
