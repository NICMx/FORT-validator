#include "rtr/db/db_table.h"

#include <errno.h>

#include "alloc.h"
#include "config.h"
#include "data_structure/uthash.h"
#include "log.h"
#include "types/aspa.h"

struct hashable_roa {
	struct vrp data;
	UT_hash_handle hh;
};

struct hashable_key {
	struct router_key data;
	UT_hash_handle hh;
};

struct hashable_aspa {
	struct aspa *v;
	UT_hash_handle hh;
};

struct db_table {
	struct hashable_roa *roas;
	struct hashable_key *router_keys;
	struct hashable_aspa *aspas;

	unsigned int total_roas_v4;
	unsigned int total_roas_v6;
};

struct db_table *
db_table_create(void)
{
	return pzalloc(sizeof(struct db_table));
}

void
db_table_destroy(struct db_table *table)
{
	struct hashable_roa *roa, *tmpr;
	struct hashable_key *rk, *tmpk;

	if (table == NULL)
		return;

	HASH_ITER(hh, table->roas, roa, tmpr) {
		HASH_DEL(table->roas, roa);
		free(roa);
	}

	HASH_ITER(hh, table->router_keys, rk, tmpk) {
		HASH_DEL(table->router_keys, rk);
		free(rk);
	}

	free(table);
}

static int
add_roa(struct db_table *table, struct hashable_roa *new)
{
	struct hashable_roa *old;
	int error;

	errno = 0;
	HASH_REPLACE(hh, table->roas, data, sizeof(new->data), new, old);
	error = errno;

	if (error) {
		pr_val_err("ROA couldn't be added to hash table: %s",
		    strerror(error));
		return -error;
	}

	if (old == NULL) {
		switch (new->data.addr_fam) {
		case AF_INET:	table->total_roas_v4++; break;
		case AF_INET6:	table->total_roas_v6++; break;
		}
	} else {
		free(old);
	}

	return 0;
}

static int
add_router_key(struct db_table *table, struct hashable_key *new)
{
	struct hashable_key *old;
	int error;

	errno = 0;
	HASH_REPLACE(hh, table->router_keys, data, sizeof(new->data), new, old);
	error = errno;
	if (error) {
		pr_val_err("Router Key couldn't be added to hash table: %s",
		    strerror(error));
		return -error;
	}
	if (old != NULL)
		free(old);

	return 0;
}

/* Assumes the lists are already sorted. Places the result in @new. */
static struct aspa_providers
merge_providers(struct aspa_providers *old, struct aspa_providers *new)
{
	struct aspa_providers result;
	uint32_t *merge;
	size_t o, n, m;

	m = old->count + new->count;
	if (!old->asids || m > config_get_max_aspa_providers()) {
		result.asids = NULL;
		result.count = 0;
		return result;
	}

	merge = pcalloc(m, sizeof(uint32_t));

	for (o = 0, n = 0, m = 0; o < old->count && n < new->count;) {
		if (old->asids[o] < new->asids[n]) {
			merge[m] = old->asids[o];
			o++;
			m++;
		} else if (old->asids[o] > new->asids[n]) {
			merge[m] = new->asids[n];
			n++;
			m++;
		} else
			o++;
	}

	for (; o < old->count; o++, m++)
		merge[m] = old->asids[o];
	for (; n < new->count; n++, m++)
		merge[m] = new->asids[n];

	result.asids = merge;
	result.count = m;
	return result;
}

static int
add_aspa(struct db_table *table, struct hashable_aspa *new)
{
	struct hashable_aspa *old;
	struct aspa_providers merge;
	int error;

	pr_val_debug("Adding ASPA for customer %u", new->v->customer);

	errno = 0;
	HASH_REPLACE(hh, table->aspas, v->customer, sizeof(new->v->customer),
	    new, old);
	error = errno;
	if (error) {
		pr_val_err("Cannot store ASPA: %s", strerror(error));
		return -error;
	}

	if (old != NULL) {
		merge = merge_providers(&old->v->providers, &new->v->providers);

		free(new->v->providers.asids);
		new->v->providers = merge;

		free(old->v->providers.asids);
		free(old);
	}

	return 0;
}

/* Moves the content from @src into @dst. */
int
db_table_join(struct db_table *dst, struct db_table *src)
{
	struct hashable_roa *roa, *tmpr;
	struct hashable_key *rk, *tmpk;
	struct hashable_aspa *aspa, *tmpa;
	int error;

	HASH_ITER(hh, src->roas, roa, tmpr) {
		HASH_DEL(src->roas, roa);
		error = add_roa(dst, roa);
		if (error)
			return error;
	}

	HASH_ITER(hh, src->router_keys, rk, tmpk) {
		HASH_DEL(src->router_keys, rk);
		error = add_router_key(dst, rk);
		if (error)
			return error;
	}

	HASH_ITER(hh, src->aspas, aspa, tmpa) {
		HASH_DEL(src->aspas, aspa);
		error = add_aspa(dst, aspa);
		if (error)
			return error;
	}

	return 0;
}

int
db_table_foreach_roa(struct db_table const *table, vrp_foreach_cb cb, void *arg)
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
db_table_foreach_router_key(struct db_table const *table,
    router_key_foreach_cb cb, void *arg)
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

int
db_table_foreach_aspa(struct db_table const *table, aspa_foreach_cb cb,
    void *arg)
{
	struct hashable_aspa *node, *tmp;
	int error;

	HASH_ITER(hh, table->aspas, node, tmp) {
		error = cb(node->v, arg);
		if (error)
			return error;
	}

	return 0;
}

unsigned int
db_table_roa_count(struct db_table *table)
{
	return HASH_COUNT(table->roas);
}

unsigned int
db_table_roa_count_v4(struct db_table *table)
{
	return table->total_roas_v4;
}

unsigned int
db_table_roa_count_v6(struct db_table *table)
{
	return table->total_roas_v6;
}

unsigned int
db_table_router_key_count(struct db_table *table)
{
	return HASH_COUNT(table->router_keys);
}

unsigned int
db_table_aspa_count(struct db_table *table)
{
	return HASH_COUNT(table->aspas);
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

void
db_table_remove_router_key(struct db_table *table,
    struct router_key const *del)
{
	struct hashable_key *ptr;

	HASH_FIND(hh, table->router_keys, del, sizeof(*del), ptr);
	if (ptr != NULL) {
		HASH_DELETE(hh, table->router_keys, ptr);
		free(ptr);
	}
}

int
rtrhandler_handle_roa_v4(struct db_table *table, uint32_t asn,
    struct ipv4_prefix const *prefix4, uint8_t max_length)
{
	struct hashable_roa *roa = pzalloc(sizeof(struct hashable_roa));

	roa->data.asn = asn;
	roa->data.prefix.v4 = prefix4->addr;
	roa->data.prefix_length = prefix4->len;
	roa->data.max_prefix_length = max_length;
	roa->data.addr_fam = AF_INET;

	return add_roa(table, roa);
}

int
rtrhandler_handle_roa_v6(struct db_table *table, uint32_t asn,
    struct ipv6_prefix const *prefix6, uint8_t max_length)
{
	struct hashable_roa *roa = pzalloc(sizeof(struct hashable_roa));

	roa->data.asn = asn;
	roa->data.prefix.v6 = prefix6->addr;
	roa->data.prefix_length = prefix6->len;
	roa->data.max_prefix_length = max_length;
	roa->data.addr_fam = AF_INET6;

	return add_roa(table, roa);
}

int
rtrhandler_handle_router_key(struct db_table *table, unsigned char const *ski,
    uint32_t as, unsigned char const *spk)
{
	struct hashable_key *key;
	int error;

	key = pzalloc(sizeof(struct hashable_key)); /* Zero needed by uthash */

	router_key_init(&key->data, ski, as, spk);

	error = add_router_key(table, key);
	if (error)
		free(key);

	return error;
}

int
rtrhandler_handle_aspa(struct db_table *table, struct aspa *v)
{
	struct hashable_aspa *aspa;
	int error;

	aspa = pzalloc(sizeof(struct hashable_aspa));
	aspa->v = v;

	error = add_aspa(table, aspa);
	if (error)
		free(aspa);
	else
		aspa_refget(v);

	return error;
}

/*
 * Copies `@roas1 - roas2` into @deltas.
 *
 * (Places the ROAs that exist in @roas1 but not in @roas2 in @deltas.)
 */
static int
add_roa_deltas(struct hashable_roa *roas1, struct hashable_roa *roas2,
    struct deltas *deltas, int op, char r1type)
{
	struct hashable_roa *n1; /* A node from @roas1 */
	struct hashable_roa *n2; /* A node from @roas2 */
	struct hashable_roa *tmp;
	unsigned int r;
	unsigned int roa1_count;

	r = 0;
	roa1_count = HASH_COUNT(roas1);

	HASH_ITER(hh, roas1, n1, tmp) {
		HASH_FIND(hh, roas2, &n1->data, sizeof(n1->data), n2);
		if (n2 == NULL)
			deltas_add_roa(deltas, &n1->data, op, r1type, r,
			    roa1_count);
		r++;
	}

	return 0;
}

/*
 * Copies `@keys1 - keys2` into @deltas.
 *
 * (Places the Router Keys that exist in @keys1 but not in @key2 in @deltas.)
 */
static void
add_router_key_deltas(struct hashable_key *keys1, struct hashable_key *keys2,
    struct deltas *deltas, int op)
{
	struct hashable_key *n1; /* A node from @keys1 */
	struct hashable_key *n2; /* A node from @keys2 */

	for (n1 = keys1; n1 != NULL; n1 = n1->hh.next) {
		HASH_FIND(hh, keys2, &n1->data, sizeof(n1->data), n2);
		if (n2 == NULL)
			deltas_add_router_key(deltas, &n1->data, op);
	}
}

static void
add_aspa_announcements(struct hashable_aspa *old, struct hashable_aspa *new,
    struct deltas *deltas)
{
	struct hashable_aspa *o, *n, *tmp;

	HASH_ITER(hh, new, n, tmp) {
		HASH_FIND(hh, old, &n->v->customer, sizeof(n->v->customer), o);
		if (o == NULL || !providers_equal(&o->v->providers, &n->v->providers))
			deltas_add_aspa(deltas, n->v, FLAG_ANNOUNCEMENT);
	}
}

static void
add_aspa_withdraws(struct hashable_aspa *old, struct hashable_aspa *new,
    struct deltas *deltas)
{
	struct hashable_aspa *o, *n, *tmp;

	HASH_ITER(hh, old, o, tmp) {
		HASH_FIND(hh, new, &o->v->customer, sizeof(o->v->customer), n);
		if (n == NULL)
			deltas_add_aspa(deltas, o->v, FLAG_WITHDRAWAL);
	}
}

struct deltas *
compute_deltas(struct db_table *old, struct db_table *new)
{
	struct deltas *deltas = deltas_create();

	add_roa_deltas(new->roas, old->roas, deltas, FLAG_ANNOUNCEMENT, 'n');
	add_roa_deltas(old->roas, new->roas, deltas, FLAG_WITHDRAWAL, 'o');
	add_router_key_deltas(new->router_keys, old->router_keys, deltas,
	    FLAG_ANNOUNCEMENT);
	add_router_key_deltas(old->router_keys, new->router_keys, deltas,
	    FLAG_WITHDRAWAL);
	add_aspa_announcements(old->aspas, new->aspas, deltas);
	add_aspa_withdraws(old->aspas, new->aspas, deltas);

	if (deltas_is_empty(deltas)) {
		deltas_refput(deltas);
		return NULL;
	}

	return deltas;
}
