#include "rtr/db/delta.h"

#include <stdatomic.h>
#include <string.h>

#include "data_structure/array_list.h"
#include "log.h"
#include "types/address.h"

struct delta_v4 {
	uint32_t as;
	struct ipv4_prefix prefix;
	uint8_t max_length;
};

struct delta_v6 {
	uint32_t as;
	struct ipv6_prefix prefix;
	uint8_t max_length;
};

struct delta_rk {
	unsigned char	ski[RK_SKI_LEN];
	uint32_t	as;
	unsigned char	spk[RK_SPKI_LEN];
};

struct _delta_aspa {
	struct aspa *aspa;
};

STATIC_ARRAY_LIST(deltas_v6, struct delta_v6)
STATIC_ARRAY_LIST(deltas_v4, struct delta_v4)
STATIC_ARRAY_LIST(deltas_rk, struct delta_rk)
STATIC_ARRAY_LIST(deltas_aspa, struct _delta_aspa)

struct deltas {
	struct {
		struct deltas_v4 adds;
		struct deltas_v4 removes;
	} v4;
	struct {
		struct deltas_v6 adds;
		struct deltas_v6 removes;
	} v6;
	struct {
		struct deltas_rk adds;
		struct deltas_rk removes;
	} rk;
	struct {
		struct deltas_aspa adds;
		struct deltas_aspa removes;
	} aspa;

	atomic_uint references;
};

struct deltas *
deltas_create(void)
{
	struct deltas *result;

	result = pmalloc(sizeof(struct deltas));

	deltas_v4_init(&result->v4.adds);
	deltas_v4_init(&result->v4.removes);
	deltas_v6_init(&result->v6.adds);
	deltas_v6_init(&result->v6.removes);
	deltas_rk_init(&result->rk.adds);
	deltas_rk_init(&result->rk.removes);
	deltas_aspa_init(&result->aspa.adds);
	deltas_aspa_init(&result->aspa.removes);
	atomic_init(&result->references, 1);

	return result;
}

void
deltas_refget(struct deltas *deltas)
{
	atomic_fetch_add(&deltas->references, 1);
}

void
deltas_refput(struct deltas *deltas)
{
	/*
	 * Reminder: atomic_fetch_sub() returns the previous value, not the
	 * resulting one.
	 */
	if (atomic_fetch_sub(&deltas->references, 1) == 1) {
		deltas_v4_cleanup(&deltas->v4.adds, NULL);
		deltas_v4_cleanup(&deltas->v4.removes, NULL);
		deltas_v6_cleanup(&deltas->v6.adds, NULL);
		deltas_v6_cleanup(&deltas->v6.removes, NULL);
		deltas_rk_cleanup(&deltas->rk.adds, NULL);
		deltas_rk_cleanup(&deltas->rk.removes, NULL);
		deltas_aspa_cleanup(&deltas->aspa.adds, NULL);
		deltas_aspa_cleanup(&deltas->aspa.removes, NULL);
		free(deltas);
	}
}

static struct deltas_v4 *
get_deltas_array4(struct deltas *deltas, int op)
{
	switch (op) {
	case FLAG_ANNOUNCEMENT:
		return &deltas->v4.adds;
	case FLAG_WITHDRAWAL:
		return &deltas->v4.removes;
	}

	pr_crit("Unknown delta operation: %d", op);
	return NULL; /* Warning shutupper */
}

static struct deltas_v6 *
get_deltas_array6(struct deltas *deltas, int op)
{
	switch (op) {
	case FLAG_ANNOUNCEMENT:
		return &deltas->v6.adds;
	case FLAG_WITHDRAWAL:
		return &deltas->v6.removes;
	}

	pr_crit("Unknown delta operation: %d", op);
	return NULL; /* Warning shutupper */
}

void
deltas_add_roa(struct deltas *deltas, struct vrp const *vrp, int op,
    char r1type, unsigned int roa_counter, unsigned int roa_count)
{
	union {
		struct delta_v4 v4;
		struct delta_v6 v6;
	} delta;
	char buffer[INET6_ADDRSTRLEN];

	switch (vrp->addr_fam) {
	case AF_INET:
		delta.v4.as = vrp->asn;
		delta.v4.prefix.addr = vrp->prefix.v4;
		delta.v4.prefix.len = vrp->prefix_length;
		delta.v4.max_length = vrp->max_prefix_length;
		deltas_v4_add(get_deltas_array4(deltas, op), &delta.v4);
		return;
	case AF_INET6:
		delta.v6.as = vrp->asn;
		delta.v6.prefix.addr = vrp->prefix.v6;
		delta.v6.prefix.len = vrp->prefix_length;
		delta.v6.max_length = vrp->max_prefix_length;
		deltas_v6_add(get_deltas_array6(deltas, op), &delta.v6);
		return;
	}

	pr_crit("Unknown protocol: [%u %s/%u-%u %u] %c %u/%u "
	    "(Please report this output to https://github.com/NICMx/FORT-validator/issues/89)",
	    vrp->asn,
	    addr2str6(&vrp->prefix.v6, buffer),
	    vrp->prefix_length,
	    vrp->max_prefix_length,
	    vrp->addr_fam,
	    r1type,
	    roa_counter,
	    roa_count);
}

void
deltas_add_router_key(struct deltas *deltas, struct router_key const *key,
    int op)
{
	struct delta_rk delta = {
		.as = key->as,
	};
	memcpy(delta.ski, key->ski, RK_SKI_LEN);
	memcpy(delta.spk, key->spk, RK_SPKI_LEN);

	switch (op) {
	case FLAG_ANNOUNCEMENT:
		deltas_rk_add(&deltas->rk.adds, &delta);
		return;
	case FLAG_WITHDRAWAL:
		deltas_rk_add(&deltas->rk.removes, &delta);
		return;
	}

	pr_crit("Unknown delta operation: %d", op);
}

void
deltas_add_aspa(struct deltas *deltas, struct aspa *aspa, int op)
{
	struct _delta_aspa delta;

	delta.aspa = aspa;
	aspa_refget(aspa);

	switch (op) {
	case FLAG_ANNOUNCEMENT:
		deltas_aspa_add(&deltas->aspa.adds, &delta);
		return;
	case FLAG_WITHDRAWAL:
		deltas_aspa_add(&deltas->aspa.removes, &delta);
		return;
	}

	pr_crit("Unknown delta operation: %d", op);
}

bool
deltas_is_empty(struct deltas *deltas)
{
	return (deltas->v4.adds.len == 0)
	    && (deltas->v4.removes.len == 0)
	    && (deltas->v6.adds.len == 0)
	    && (deltas->v6.removes.len == 0)
	    && (deltas->rk.adds.len == 0)
	    && (deltas->rk.removes.len == 0)
	    && (deltas->aspa.adds.len == 0)
	    && (deltas->aspa.removes.len == 0);
}

static int
__foreach_v4(struct deltas_v4 *array, delta_vrp_foreach_cb cb, void *arg,
    uint8_t flags)
{
	struct delta_vrp delta;
	struct delta_v4 *d;
	int error;

	delta.vrp.addr_fam = AF_INET;
	delta.flags = flags;

	ARRAYLIST_FOREACH(array, d) {
		delta.vrp.asn = d->as;
		delta.vrp.prefix.v4 = d->prefix.addr;
		delta.vrp.prefix_length = d->prefix.len;
		delta.vrp.max_prefix_length = d->max_length;
		error = cb(&delta, arg);
		if (error)
			return error;
	}

	return 0;
}

static int
__foreach_v6(struct deltas_v6 *array, delta_vrp_foreach_cb cb, void *arg,
    uint8_t flags)
{
	struct delta_vrp delta;
	struct delta_v6 *d;
	int error;

	delta.vrp.addr_fam = AF_INET6;
	delta.flags = flags;

	ARRAYLIST_FOREACH(array, d) {
		delta.vrp.asn = d->as;
		delta.vrp.prefix.v6 = d->prefix.addr;
		delta.vrp.prefix_length = d->prefix.len;
		delta.vrp.max_prefix_length = d->max_length;
		error = cb(&delta, arg);
		if (error)
			return error;
	}

	return 0;
}

static int
__foreach_rk(struct deltas_rk *array,  delta_router_key_foreach_cb cb,
    void *arg, uint8_t flags)
{
	struct delta_router_key delta;
	struct delta_rk *d;
	int error;

	delta.flags = flags;

	ARRAYLIST_FOREACH(array, d) {
		delta.router_key.as = d->as;
		memcpy(delta.router_key.ski, d->ski, RK_SKI_LEN);
		memcpy(delta.router_key.spk, d->spk, RK_SPKI_LEN);
		error = cb(&delta, arg);
		if (error)
			return error;
	}

	return 0;
}

static int
__foreach_aspa(struct deltas_aspa *array, delta_aspa_foreach_cb cb, void *arg,
    uint8_t flags)
{
	struct delta_aspa delta;
	struct _delta_aspa *d;
	int error;

	delta.flags = flags;

	ARRAYLIST_FOREACH(array, d) {
		delta.aspa = d->aspa;
		error = cb(&delta, arg);
		if (error)
			return error;
	}

	return 0;
}

int
deltas_foreach(struct deltas *deltas, delta_vrp_foreach_cb cb_vrp,
    delta_router_key_foreach_cb cb_rk, delta_aspa_foreach_cb cb_aspa,
    void *arg)
{
	int error;

	error = __foreach_v4(&deltas->v4.adds, cb_vrp, arg, FLAG_ANNOUNCEMENT);
	if (error)
		return error;
	error = __foreach_v4(&deltas->v4.removes, cb_vrp, arg, FLAG_WITHDRAWAL);
	if (error)
		return error;
	error = __foreach_v6(&deltas->v6.adds, cb_vrp, arg, FLAG_ANNOUNCEMENT);
	if (error)
		return error;
	error = __foreach_v6(&deltas->v6.removes, cb_vrp, arg, FLAG_WITHDRAWAL);
	if (error)
		return error;
	error = __foreach_rk(&deltas->rk.adds, cb_rk, arg, FLAG_ANNOUNCEMENT);
	if (error)
		return error;
	error = __foreach_rk(&deltas->rk.removes, cb_rk, arg, FLAG_WITHDRAWAL);
	if (error)
		return error;
	error = __foreach_aspa(&deltas->aspa.adds, cb_aspa, arg, FLAG_ANNOUNCEMENT);
	if (error)
		return error;
	return __foreach_aspa(&deltas->aspa.removes, cb_aspa, arg, FLAG_WITHDRAWAL);
}

void
deltas_print(struct deltas *deltas)
{
	deltas_foreach(deltas, delta_vrp_print, delta_rk_print, delta_aspa_print, NULL);
}
