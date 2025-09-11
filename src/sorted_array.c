#include "sorted_array.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "alloc.h"
#include "log.h"

struct sorted_array {
	void *array;
	/* Actual number of elements in @array */
	unsigned int count;
	/* Total allocated slots in @array */
	unsigned int len;
	/* Size of each array element */
	size_t size;
	/* Comparison function for element insertion */
	sarray_cmp cmp;

	unsigned int refcount;
};

struct sorted_array *
sarray_create(size_t elem_size, sarray_cmp cmp)
{
	struct sorted_array *result;

	result = pmalloc(sizeof(struct sorted_array));

	result->array = pcalloc(8, elem_size);
	result->count = 0;
	result->len = 8;
	result->size = elem_size;
	result->cmp = cmp;
	result->refcount = 1;

	return result;
}

void
sarray_get(struct sorted_array *sarray)
{
	sarray->refcount++;
}

void
sarray_put(struct sorted_array *sarray)
{
	sarray->refcount--;
	if (sarray->refcount == 0) {
		free(sarray->array);
		free(sarray);
	}
}

/* Does not check boundaries. */
static void *
get_nth_element(struct sorted_array const *sarray, unsigned int index)
{
	return ((char *)sarray->array) + index * sarray->size;
}

/**
 * Returns success only if @new can be added to @array.
 * (Meaning, returns success if @new is larger than all of the elements in
 * @array.)
 */
static int
compare(struct sorted_array *sarray, void const *new)
{
	enum sarray_comparison cmp;

	if (sarray->count == 0)
		return 0;

	cmp = sarray->cmp(get_nth_element(sarray, sarray->count - 1), new);
	switch (cmp) {
	case SACMP_EQUAL:
		return -EEQUAL;
	case SACMP_CHILD:
		return -ECHILD2;
	case SACMP_PARENT:
		return -EPARENT;
	case SACMP_LEFT:
		return -ELEFT;
	case SACMP_RIGHT:
		return 0;
	case SACMP_ADJACENT_LEFT:
		return -EADJLEFT;
	case SACMP_ADJACENT_RIGHT:
		return -EADJRIGHT;
	case SACMP_INTERSECTION:
		return -EINTERSECTION;
	}

	pr_crit("Unknown comparison value: %u", cmp);
}

int
sarray_add(struct sorted_array *sarray, void const *element)
{
	int error;

	error = compare(sarray, element);
	if (error)
		return error;

	if (sarray->count >= sarray->len) {
		sarray->array = realloc(sarray->array,
		    2 * sarray->len * sarray->size);
		sarray->len *= 2;
	}

	memcpy(get_nth_element(sarray, sarray->count), element, sarray->size);
	sarray->count++;
	return 0;
}

bool
sarray_empty(struct sorted_array const *sarray)
{
	return (sarray == NULL) || (sarray->count == 0);
}

bool
sarray_contains(struct sorted_array const *sarray, void const *elem)
{
	unsigned int left, mid, right;
	enum sarray_comparison cmp;

	if (sarray == NULL || sarray->count == 0)
		return false;

	left = 0;
	right = sarray->count - 1;

	while (left <= right) {
		mid = left + (right - left) / 2;
		cmp = sarray->cmp(get_nth_element(sarray, mid), elem);
		switch (cmp) {
		case SACMP_LEFT:
		case SACMP_ADJACENT_LEFT:
			if (mid == 0) /* Prevents underflow */
				return false;
			right = mid - 1;
			continue;
		case SACMP_RIGHT:
		case SACMP_ADJACENT_RIGHT:
			if (mid == sarray->count - 1)
				return false;
			left = mid + 1;
			continue;
		case SACMP_EQUAL:
		case SACMP_CHILD:
			return true;
		case SACMP_PARENT:
		case SACMP_INTERSECTION:
			return false;
		}

		pr_crit("Unknown comparison value: %u", cmp);
	}

	return false;
}

int
sarray_foreach(struct sorted_array *sarray, sarray_foreach_cb cb, void *arg)
{
	unsigned int index;
	int error;

	for (index = 0; index < sarray->count; index++) {
		error = cb(get_nth_element(sarray, index), arg);
		if (error)
			return error;
	}

	return 0;
}

char const *sarray_err2str(int error)
{
	switch (abs(error)) {
	case EEQUAL:
		return "Resource equals an already existing resource";
	case ECHILD2:
		return "Resource is a subset of an already existing resource";
	case EPARENT:
		return "Resource is a superset of an already existing resource";
	case ELEFT:
		return "Resource sequence is not properly sorted";
	case EADJLEFT:
	case EADJRIGHT:
		return "Resource is adjacent to an existing resource (they are supposed to be aggregated)";
	case EINTERSECTION:
		return "Resource intersects with an already existing resource";
	}

	return strerror(error);
}
