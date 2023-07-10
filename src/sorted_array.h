#ifndef SRC_SORTED_ARRAY_H_
#define SRC_SORTED_ARRAY_H_

#include <stdbool.h>
#include <stddef.h>

/*
 * This implementation is not a generic sorted array; It's intended to store RFC
 * 3779 resources, which requires the elements to be sorted.
 * So you can only add elements to the tail of the array. The implementation
 * will validate this and prevent collisions too.
 */

struct sorted_array;

enum sarray_comparison {
	SACMP_EQUAL,
	SACMP_CHILD,
	SACMP_PARENT,
	SACMP_LEFT,
	SACMP_RIGHT,
	SACMP_ADJACENT_LEFT,
	SACMP_ADJACENT_RIGHT,
	SACMP_INTERSECTION,
};

typedef enum sarray_comparison (*sarray_cmp)(void const *, void const *);

struct sorted_array *sarray_create(size_t, sarray_cmp);
void sarray_get(struct sorted_array *);
void sarray_put(struct sorted_array *);

#define EEQUAL		7894
#define ECHILD2		7895
#define EPARENT		7896
#define ELEFT		7897
#define EADJLEFT	7898
#define EADJRIGHT	7899
#define EINTERSECTION	7900

int sarray_add(struct sorted_array *, void const *);
bool sarray_empty(struct sorted_array const *);
bool sarray_contains(struct sorted_array const *, void const *);

typedef int (*sarray_foreach_cb)(void *, void *);
int sarray_foreach(struct sorted_array *, sarray_foreach_cb, void *);

char const *sarray_err2str(int);

#endif /* SRC_SORTED_ARRAY_H_ */
