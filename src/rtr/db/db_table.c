#include "rtr/db/db_table.h"

#include "alloc.h"
#include "config.h"
#include "data_structure/common.h"
#include "data_structure/uthash.h"
#include "file.h"
#include "log.h"
#include "rtr/meta.h"

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

	struct rtr_index rtr;
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
	struct hashable_aspa *aspa, *tmpa;

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

	HASH_ITER(hh, table->aspas, aspa, tmpa) {
		HASH_DEL(table->aspas, aspa);
		aspa_refput(aspa->v);
		free(aspa);
	}

	rtridx_cleanup(&table->rtr);

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
		free(old->v);
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
		if (error) {
			free(roa);
			return error;
		}
	}

	HASH_ITER(hh, src->router_keys, rk, tmpk) {
		HASH_DEL(src->router_keys, rk);
		error = add_router_key(dst, rk);
		if (error) {
			free(rk);
			return error;
		}
	}

	HASH_ITER(hh, src->aspas, aspa, tmpa) {
		HASH_DEL(src->aspas, aspa);
		error = add_aspa(dst, aspa);
		if (error) {
			aspa_refput(aspa->v);
			free(aspa);
			return error;
		}
	}

	return 0;
}

static int
cmp_u8(uint8_t a, uint8_t b)
{
	/* JIC the platform typedefs uintXX_ts into unsigned ints */
	a &= 0xFFu;
	b &= 0xFFu;

	if (a > b) return 1;
	if (a < b) return -1;
	return 0;
}

static int
cmp_u32(uint32_t a, uint32_t b)
{
	a = htonl(a);
	b = htonl(b);
	return memcmp(&a, &b, 4);
}

static int
cmp_vrp(struct hashable_roa *_a, struct hashable_roa *_b)
{
	struct vrp *a = &_a->data;
	struct vrp *b = &_b->data;
	int cmp;

	cmp = cmp_u8(a->addr_fam, b->addr_fam);
	if (cmp) return cmp;

	switch (a->addr_fam) {
	case AF_INET:  cmp = memcmp(&b->prefix.v4, &a->prefix.v4, 4);  break;
	case AF_INET6: cmp = memcmp(&b->prefix.v6, &a->prefix.v6, 16); break;
	}
	if (cmp) return cmp;

	cmp = cmp_u8(b->max_prefix_length, a->max_prefix_length);
	if (cmp) return cmp;

	cmp = cmp_u8(b->prefix_length, a->prefix_length);
	if (cmp) return cmp;

	return cmp_u32(b->asn, a->asn);
}

static int
cmp_rk(struct hashable_key *_a, struct hashable_key *_b)
{
	struct router_key *a = &_a->data;
	struct router_key *b = &_b->data;
	int cmp;

	cmp = memcmp(a->ski, b->ski, RK_SKI_LEN);
	if (cmp) return cmp;
	cmp = memcmp(a->spk, b->spk, RK_SPKI_LEN);
	if (cmp) return cmp;
	return cmp_u32(a->as, b->as);
}

static int
cmp_aspa(struct hashable_aspa *a, struct hashable_aspa *b)
{
	return cmp_u32(a->v->customer, b->v->customer);
}

void
db_table_sort(struct db_table *table)
{
	HASH_SORT(table->roas, cmp_vrp);
	HASH_SORT(table->router_keys, cmp_rk);
	HASH_SORT(table->aspas, cmp_aspa);
}

static int
mkdir_f(char const *path)
{
	int error;

	pr_op_debug("mkdir -f %s", path);

	if (mkdir(path, 0777) < 0) {
		error = errno;
		if (error != EEXIST) {
			pr_op_err("Cannot create directory '%s': %s",
			    path, strerror(error));
			return error;
		}
	}

	return 0;
}

static int
write_u8(FILE *file, uint8_t v)
{
	return (fwrite(&v, 1, 1, file) != 1)
	    ? pr_op_err("fwrite() could not write 1 byte.")
	    : 0;
}

static int
write_u32(FILE *file, uint32_t v)
{
	v = htonl(v);
	return (fwrite(&v, 4, 1, file) != 1)
	    ? pr_op_err("fwrite() could not write 4 bytes.")
	    : 0;
}

static int
write_buf(FILE *file, unsigned char *buf, size_t len)
{
	return (fwrite(buf, len, 1, file) != 1)
	    ? pr_op_err("fwrite() could not write %zu bytes.", len)
	    : 0;
}

static int
write_addr(FILE *file, struct vrp *vrp)
{
	switch (vrp->addr_fam) {
	case AF_INET:  return write_buf(file, (unsigned char *)&vrp->prefix, 4);
	case AF_INET6: return write_buf(file, (unsigned char *)&vrp->prefix, 16);
	}
	return EINVAL;
}

static int
cache_vrps(struct db_table *table, serial_t serial)
{
	FILE *f4 = NULL;
	FILE *f6 = NULL;
	FILE *file;
	struct hashable_roa *hvrp, *tmpv;
	struct vrp *vrp;
	int err;

	err = rtr_open_file(serial, "vrp4", "w", &f4);
	if (err)
		return err;
	err = rtr_open_file(serial, "vrp6", "w", &f6);
	if (err)
		goto end;

	HASH_ITER(hh, table->roas, hvrp, tmpv) {
		vrp = &hvrp->data;

		switch (vrp->addr_fam) {
		case AF_INET:  file = f4; break;
		case AF_INET6: file = f6; break;
		default:       continue;
		}

		if ((err = write_u32(file, vrp->asn)) != 0)
			goto end;
		if ((err = write_addr(file, vrp)) != 0)
			goto end;
		if ((err = write_u8(file, vrp->prefix_length)) != 0)
			goto end;
		if ((err = write_u8(file, vrp->max_prefix_length)) != 0)
			goto end;
	}

end:	if (f4) fclose(f4);
	if (f6) fclose(f6);
	return err;
}

static int
cache_rks(struct db_table *table, serial_t serial)
{
	FILE *file = NULL;
	struct hashable_key *rk, *tmpr;
	int err;

	err = rtr_open_file(serial, "rk", "w", &file);
	if (err)
		return err;

	HASH_ITER(hh, table->router_keys, rk, tmpr) {
		if ((err = write_u32(file, rk->data.as)) != 0)
			break;
		if ((err = write_buf(file, rk->data.ski, RK_SKI_LEN)) != 0)
			break;
		if ((err = write_buf(file, rk->data.spk, RK_SPKI_LEN)) != 0)
			break;
	}

	fclose(file);
	return err;
}

static int
cache_aspas(struct db_table *table, serial_t serial)
{
	FILE *file = NULL;
	struct hashable_aspa *aspa, *tmpa;
	array_index i;
	int err;

	err = rtr_open_file(serial, "aspa", "w", &file);
	if (err)
		return err;

	HASH_ITER(hh, table->aspas, aspa, tmpa) {
		if ((err = write_u32(file, aspa->v->customer)) != 0)
			break;
		if ((err = write_u32(file, aspa->v->providers.count)) != 0)
			break;
		for (i = 0; i < aspa->v->providers.count; i++)
			if ((err = write_u32(file, aspa->v->providers.asids[i])) != 0)
				break;
	}

	fclose(file);
	return err;
}

static int
cache_metadata(struct db_table *table)
{
	char *dir;
	int error;

	error = rtridx_save(&table->rtr);
	if (error) {
		pr_op_err("Could not save RTR metadata; RTR can no longer be served.");
		dir = rtr_filename(NULL, NULL);
		file_rm_rf(dir);
		free(dir);
	}

	return error;
}

int
db_table_cache(struct db_table *table)
{
	char *path;
	serial_t serial;
	int ret;

	ret = rtridx_load(&table->rtr, true);
	if (ret == ENOENT)
		rtridx_init(&table->rtr);
	else if (ret) {
		pr_op_err("Cannot access RTR index file: %s", strerror(ret));
		return ret;
	}

	serial = rtridx_add_serial(&table->rtr);

	path = rtr_filename(NULL, NULL); /* cache/rtr */
	ret = mkdir_f(path);
	free(path);
	if (ret)
		return ret;

	path = rtr_filename2(serial, NULL); /* cache/rtr/1234 */
	ret = mkdir_f(path);
	free(path);
	if (ret)
		return ret;

	ret = cache_vrps(table, serial);
	if (ret)
		goto fail;
	ret = cache_rks(table, serial);
	if (ret)
		goto fail;
	ret = cache_aspas(table, serial);
	if (ret)
		goto fail;
	ret = cache_metadata(table);
	if (ret)
		goto fail;
	rtridx_clean(&table->rtr);

	return 0;

fail:	path = rtr_filename2(serial, NULL);
	file_rm_rf(path);
	free(path);
	return ret;
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
	return table ? HASH_COUNT(table->roas) : 0;
}

unsigned int
db_table_roa_count_v4(struct db_table *table)
{
	return table ? table->total_roas_v4 : 0;
}

unsigned int
db_table_roa_count_v6(struct db_table *table)
{
	return table ? table->total_roas_v6 : 0;
}

unsigned int
db_table_router_key_count(struct db_table *table)
{
	return table ? HASH_COUNT(table->router_keys) : 0;
}

unsigned int
db_table_aspa_count(struct db_table *table)
{
	return table ? HASH_COUNT(table->aspas) : 0;
}

uint16_t
db_table_session(struct db_table *table)
{
	return table ? table->rtr.session : 0;
}

serial_t
db_table_serial(struct db_table *table)
{
	return (table && table->rtr.serials) ? table->rtr.serials->serial : 0;
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
