#include "rtr/db/deltas_array.h"

#include <errno.h>
#include <limits.h>

#include "alloc.h"
#include "config.h"
#include "log.h"

struct deltas_array {
	struct deltas **array; /* It's a circular array. */
	unsigned int len; /* Occupied slots. */
	unsigned int last; /* Index of last added element. */
};

struct deltas_array *
darray_create(void)
{
	struct deltas_array *result;

	result = pmalloc(sizeof(struct deltas_array));

	result->array = pcalloc(config_get_deltas_lifetime(),
	    sizeof(struct deltas *));
	result->len = 0;
	result->last = UINT_MAX;

	return result;
}

void
darray_destroy(struct deltas_array *darray)
{
	darray_clear(darray);
	free(darray->array);
	free(darray);
}

unsigned int
darray_len(struct deltas_array *darray)
{
	return darray->len;
}

void
darray_add(struct deltas_array *darray, struct deltas *addend)
{
	unsigned int first;

	if (darray->len < config_get_deltas_lifetime()) {
		darray->array[darray->len] = addend;
		darray->last = darray->len;
		darray->len++;
	} else {
		first = (darray->last == darray->len - 1)
		    ? 0 : (darray->last + 1);
		deltas_refput(darray->array[first]);
		darray->array[first] = addend;
		darray->last = first;
	}
}

void
darray_clear(struct deltas_array *darray)
{
	unsigned int i;
	for (i = 0; i < darray->len; i++)
		deltas_refput(darray->array[i]);
	darray->len = 0;
}

int
darray_foreach_since(struct deltas_array *darray, unsigned int from,
    darray_foreach_cb cb, void *arg)
{
	unsigned int i;
	unsigned int j;
	int error;

	if (from == 0)
		return 0;
	if (from > darray->len)
		return -EINVAL;

	i = darray->last - from + 1;
	if (i > darray->len)
		i += darray->len;

	from += i;
	for (; i < from; i++) {
		j = (i >= darray->len) ? (i - darray->len) : i;
		error = cb(darray->array[j], arg);
		if (error)
			return error;
	}

	return 0;

}
