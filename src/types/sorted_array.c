#include "types/sorted_array.h"

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
static enum resource_cmp_result
compare(struct sorted_array *sarray, void const *new)
{
	enum sarray_comparison cmp;

	if (sarray->count == 0)
		return RCR_OK;

	cmp = sarray->cmp(get_nth_element(sarray, sarray->count - 1), new);
	switch (cmp) {
	case SACMP_EQUAL:
		return RCR_EEQUAL;
	case SACMP_CHILD:
		return RCR_ECHILD2;
	case SACMP_PARENT:
		return RCR_EPARENT;
	case SACMP_LEFT:
		return RCR_ELEFT;
	case SACMP_RIGHT:
		return RCR_OK;
	case SACMP_ADJACENT_LEFT:
		return RCR_EADJLEFT;
	case SACMP_ADJACENT_RIGHT:
		return RCR_EADJRIGHT;
	case SACMP_INTERSECTION:
		return RCR_EINTERSECTION;
	}

	pr_crit("Unknown comparison value: %u", cmp);
}

enum resource_cmp_result
sarray_add(struct sorted_array *sarray, void const *element)
{
	enum resource_cmp_result result;

	result = compare(sarray, element);
	if (result != RCR_OK)
		return result;

	if (sarray->count >= sarray->len) {
		sarray->array = realloc(sarray->array,
		    2 * sarray->len * sarray->size);
		sarray->len *= 2;
	}

	memcpy(get_nth_element(sarray, sarray->count), element, sarray->size);
	sarray->count++;
	return RCR_OK;
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

char const *
sarray_err2str(enum resource_cmp_result result)
{
	switch (result) {
	case RCR_EEQUAL:
		return "Resource equals an already existing resource";
	case RCR_ECHILD2:
		return "Resource is a subset of an already existing resource";
	case RCR_EPARENT:
		return "Resource is a superset of an already existing resource";
	case RCR_ELEFT:
		return "Resource sequence is not properly sorted";
	case RCR_EADJLEFT:
	case RCR_EADJRIGHT:
		return "Resource is adjacent to an existing resource (they are supposed to be aggregated)";
	case RCR_EINTERSECTION:
		return "Resource intersects with an already existing resource";
	case RCR_OK:
		return "Success";
	}

	return "Unknown error";
}
