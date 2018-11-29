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
	SACMP_INTERSECTION,
};

typedef enum sarray_comparison (*sarray_cmp)(void *, void *);

struct sorted_array *sarray_create(size_t, sarray_cmp);
void sarray_get(struct sorted_array *);
void sarray_put(struct sorted_array *);

#define EEQUAL		7894
#define ECHILD2		7895
#define EPARENT		7896
#define ELEFT		7897
#define EINTERSECTION	7898

int sarray_add(struct sorted_array *, void *);
int sarray_join(struct sorted_array *, struct sorted_array *);

bool sarray_contains(struct sorted_array *, void *);


#define SARRAY_API(name, type, cmp)					\
static struct sorted_array *						\
name##_create(void)							\
{									\
	return sarray_create(sizeof(struct type), cmp);			\
}									\
static void								\
name##_get(struct sorted_array *sarray)					\
{									\
	sarray_get(sarray);						\
}									\
static void								\
name##_put(struct sorted_array *sarray)					\
{									\
	sarray_put(sarray);						\
}									\
static int								\
name##_add(struct sorted_array *sarray, struct type *element)		\
{									\
	return sarray_add(sarray, element);				\
}									\
static int								\
name##_join(struct sorted_array *sarray, struct sorted_array *addend)	\
{									\
	return sarray_join(sarray, addend);				\
}									\
static bool								\
name##_contains(struct sorted_array *sarray, struct type *element)	\
{									\
	return sarray_contains(sarray, element);			\
}


#endif /* SRC_SORTED_ARRAY_H_ */
