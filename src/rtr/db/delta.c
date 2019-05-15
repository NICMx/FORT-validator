#include "rtr/db/delta.h"

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

ARRAY_LIST(deltas_v6, struct delta_v6)
ARRAY_LIST(deltas_v4, struct delta_v4)

struct deltas {
	struct {
		struct deltas_v4 adds;
		struct deltas_v4 removes;
	} v4;
	struct {
		struct deltas_v6 adds;
		struct deltas_v6 removes;
	} v6;

	/* TODO (now) atomic */
	unsigned int references;
};

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
	result->references = 1;

	*_result = result;
	return 0;
}

void
deltas_get(struct deltas *deltas)
{
	deltas->references++;
}

void
deltas_put(struct deltas *deltas)
{
	deltas->references--;
	if (deltas->references == 0) {
		deltas_v4_cleanup(&deltas->v4.adds, NULL);
		deltas_v4_cleanup(&deltas->v4.removes, NULL);
		deltas_v6_cleanup(&deltas->v6.adds, NULL);
		deltas_v6_cleanup(&deltas->v6.removes, NULL);
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

	return pr_crit("Unknown delta operation: %d", op);
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

	return pr_crit("Unknown delta operation: %d", op);
}

bool
deltas_is_empty(struct deltas *deltas)
{
	return (deltas->v4.adds.len == 0)
	    && (deltas->v4.removes.len == 0)
	    && (deltas->v6.adds.len == 0)
	    && (deltas->v6.removes.len == 0);
}

static int
__foreach_v4(struct deltas_v4 *array, delta_foreach_cb cb, void *arg,
    serial_t serial, uint8_t flags)
{
	struct delta delta;
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
__foreach_v6(struct deltas_v6 *array, delta_foreach_cb cb, void *arg,
    serial_t serial, uint8_t flags)
{
	struct delta delta;
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

int
deltas_foreach(serial_t serial, struct deltas *deltas, delta_foreach_cb cb,
    void *arg)
{
	int error;

	error = __foreach_v4(&deltas->v4.adds, cb, arg, serial,
	    FLAG_ANNOUNCEMENT);
	if (error)
		return error;

	error = __foreach_v4(&deltas->v4.removes, cb, arg, serial,
	    FLAG_WITHDRAWAL);
	if (error)
		return error;

	error = __foreach_v6(&deltas->v6.adds, cb, arg, serial,
	    FLAG_ANNOUNCEMENT);
	if (error)
		return error;

	return __foreach_v6(&deltas->v6.removes, cb, arg, serial,
	    FLAG_WITHDRAWAL);
}
