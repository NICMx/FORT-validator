#include "rtr/db/delta.h"

#include <stdatomic.h>
#include <sys/types.h> /* AF_INET, AF_INET6 (needed in OpenBSD) */
#include <sys/socket.h> /* AF_INET, AF_INET6 (needed in OpenBSD) */
#include "data_structure/array_list.h"

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

struct delta_bsec {
	uint32_t as;
	struct sk_info *sk;
};

ARRAY_LIST(deltas_v6, struct delta_v6)
ARRAY_LIST(deltas_v4, struct delta_v4)
ARRAY_LIST(deltas_bgpsec, struct delta_bsec)

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
		struct deltas_bgpsec adds;
		struct deltas_bgpsec removes;
	} bgpsec;

	atomic_uint references;
};

static void
delta_bsec_cleanup(struct delta_bsec *bsec)
{
	sk_info_refput(bsec->sk);
}

int
deltas_create(struct deltas **_result)
{
	struct deltas *result;

	result = malloc(sizeof(struct deltas));
	if (result == NULL)
		return pr_enomem();

	deltas_v4_init(&result->v4.adds);
	deltas_v4_init(&result->v4.removes);
	deltas_v6_init(&result->v6.adds);
	deltas_v6_init(&result->v6.removes);
	deltas_bgpsec_init(&result->bgpsec.adds);
	deltas_bgpsec_init(&result->bgpsec.removes);
	atomic_init(&result->references, 1);

	*_result = result;
	return 0;
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
		deltas_bgpsec_cleanup(&deltas->bgpsec.adds, delta_bsec_cleanup);
		deltas_bgpsec_cleanup(&deltas->bgpsec.removes,
		    delta_bsec_cleanup);
		free(deltas);
	}
}

int
deltas_add_roa_v4(struct deltas *deltas, uint32_t as, struct v4_address *addr,
    int op)
{
	struct delta_v4 delta = {
		.as = as,
		.prefix = addr->prefix,
		.max_length = addr->max_length,
	};

	switch (op) {
	case FLAG_ANNOUNCEMENT:
		return deltas_v4_add(&deltas->v4.adds, &delta);
	case FLAG_WITHDRAWAL:
		return deltas_v4_add(&deltas->v4.removes, &delta);
	}

	pr_crit("Unknown delta operation: %d", op);
}

int
deltas_add_roa_v6(struct deltas *deltas, uint32_t as, struct v6_address *addr,
    int op)
{
	struct delta_v6 delta = {
		.as = as,
		.prefix = addr->prefix,
		.max_length = addr->max_length,
	};

	switch (op) {
	case FLAG_ANNOUNCEMENT:
		return deltas_v6_add(&deltas->v6.adds, &delta);
	case FLAG_WITHDRAWAL:
		return deltas_v6_add(&deltas->v6.removes, &delta);
	}

	pr_crit("Unknown delta operation: %d", op);
}

int
deltas_add_bgpsec(struct deltas *deltas, struct router_key *key, int op)
{
	struct delta_bsec delta = {
		.as = key->as,
		.sk = key->sk,
	};
	sk_info_refget(key->sk);

	switch (op) {
	case FLAG_ANNOUNCEMENT:
		return deltas_bgpsec_add(&deltas->bgpsec.adds, &delta);
	case FLAG_WITHDRAWAL:
		return deltas_bgpsec_add(&deltas->bgpsec.removes, &delta);
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
	    && (deltas->bgpsec.adds.len == 0)
	    && (deltas->bgpsec.removes.len == 0);
}

static int
__foreach_v4(struct deltas_v4 *array, delta_vrp_foreach_cb cb, void *arg,
    serial_t serial, uint8_t flags)
{
	struct delta_vrp delta;
	struct delta_v4 *d;
	array_index i;
	int error;

	delta.serial = serial;
	delta.vrp.addr_fam = AF_INET;
	delta.flags = flags;

	ARRAYLIST_FOREACH(array, d, i) {
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
    serial_t serial, uint8_t flags)
{
	struct delta_vrp delta;
	struct delta_v6 *d;
	array_index i;
	int error;

	delta.serial = serial;
	delta.vrp.addr_fam = AF_INET6;
	delta.flags = flags;

	ARRAYLIST_FOREACH(array, d, i) {
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
__foreach_bgpsec(struct deltas_bgpsec *array, delta_bgpsec_foreach_cb cb,
    void *arg, serial_t serial, uint8_t flags)
{
	struct delta_bgpsec delta;
	struct delta_bsec *d;
	array_index i;
	int error;

	delta.serial = serial;
	delta.flags = flags;

	ARRAYLIST_FOREACH(array, d, i) {
		delta.router_key.as = d->as;
		delta.router_key.sk = d->sk;
		sk_info_refget(d->sk);
		error = cb(&delta, arg);
		sk_info_refput(d->sk);
		if (error)
			return error;
	}

	return 0;
}

int
deltas_foreach(serial_t serial, struct deltas *deltas,
    delta_vrp_foreach_cb cb_vrp, delta_bgpsec_foreach_cb cb_bgpsec, void *arg)
{
	int error;

	error = __foreach_v4(&deltas->v4.adds, cb_vrp, arg, serial,
	    FLAG_ANNOUNCEMENT);
	if (error)
		return error;

	error = __foreach_v4(&deltas->v4.removes, cb_vrp, arg, serial,
	    FLAG_WITHDRAWAL);
	if (error)
		return error;

	error = __foreach_v6(&deltas->v6.adds, cb_vrp, arg, serial,
	    FLAG_ANNOUNCEMENT);
	if (error)
		return error;

	error = __foreach_v6(&deltas->v6.removes, cb_vrp, arg, serial,
	    FLAG_WITHDRAWAL);
	if (error)
		return error;

	/* FIXME Temporary, this must not be null */
	if (cb_bgpsec == NULL)
		return 0;

	error = __foreach_bgpsec(&deltas->bgpsec.adds, cb_bgpsec, arg, serial,
	    FLAG_ANNOUNCEMENT);
	if (error)
		return error;

	return __foreach_bgpsec(&deltas->bgpsec.removes, cb_bgpsec, arg, serial,
	    FLAG_WITHDRAWAL);
}
