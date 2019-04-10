#ifndef SRC_DATA_STRUCTURE_ARRAY_LIST_H_
#define SRC_DATA_STRUCTURE_ARRAY_LIST_H_

#include <errno.h>
#include <stdlib.h>
#include "log.h"
#include "data_structure/common.h"

/* TODO sizes used to be unsigned ints. Check callers. */
#define DEFINE_ARRAY_LIST_STRUCT(name, elem_type)			\
	struct name {							\
		/** Unidimensional array. */				\
		elem_type *array;					\
		/** Number of elements in @array. */			\
		size_t len;						\
		/** Actual allocated slots in @array. */		\
		size_t capacity;					\
	}

#define DEFINE_ARRAY_LIST_FUNCTIONS(name, elem_type)			\
	static int							\
	name##_init(struct name *list)					\
	{								\
		list->capacity = 8;					\
		list->len = 0;						\
		/* TODO I need lazy initialization of this badly */	\
		list->array = malloc(list->capacity			\
		    * sizeof(elem_type));				\
		return (list->array != NULL) ? 0 : pr_enomem();		\
	}								\
									\
	static void							\
	name##_cleanup(struct name *list, void (*cb)(elem_type *))	\
	{								\
		array_index i;						\
		/* TODO recently added this. Use it more */		\
		if (cb != NULL)						\
			for (i = 0; i < list->len; i++)			\
				cb(&list->array[i]);			\
		free(list->array);					\
	}								\
									\
	/* Will store a shallow copy, not @elem */			\
	static int							\
	name##_add(struct name *list, elem_type *elem)			\
	{								\
		elem_type *tmp;						\
									\
		list->len++;						\
		while (list->len >= list->capacity) {			\
			list->capacity *= 2;				\
									\
			tmp = realloc(list->array, list->capacity	\
			    * sizeof(elem_type));			\
			if (tmp == NULL)				\
				return pr_enomem();			\
			list->array = tmp;				\
		}							\
									\
		list->array[list->len - 1] = *elem;			\
		return 0;						\
	}

#define ARRAY_LIST(name, elem_type)					\
	DEFINE_ARRAY_LIST_STRUCT(name, elem_type);			\
	DEFINE_ARRAY_LIST_FUNCTIONS(name, elem_type)

#define ARRAYLIST_FOREACH(list, cursor) for (				\
	cursor = (list)->array;						\
	(cursor - ((typeof(cursor)) ((list)->array))) < (list)->len;	\
	cursor++							\
)

#endif /* SRC_DATA_STRUCTURE_ARRAY_LIST_H_ */
