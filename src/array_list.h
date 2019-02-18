#ifndef SRC_ARRAY_LIST_H_
#define SRC_ARRAY_LIST_H_

#include <err.h>
#include <errno.h>

#define ARRAY_LIST(name, elem_type)					\
	struct name {							\
		/** Unidimensional array. */				\
		elem_type *array;					\
		/** Number of elements in @array. */			\
		unsigned int len;					\
		/** Actual allocated slots in @array. */		\
		unsigned int capacity;					\
	};								\
									\
	static int							\
	name##_init(struct name *list)					\
	{								\
		list->capacity = 8;					\
		list->len = 0;						\
		list->array = malloc(list->capacity			\
		    * sizeof(elem_type));				\
		return (list->array != NULL) ? 0 : -ENOMEM;		\
	}								\
									\
	static void							\
	name##_cleanup(struct name *list, void (*cb)(elem_type *))	\
	{								\
		unsigned int i;						\
		for (i = 0; i < list->len; i++)				\
			cb(&list->array[i]);				\
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
			if (tmp == NULL) {					\
				err(-ENOMEM, "Out of memory");	\
				return -ENOMEM;				\
			}							\
			list->array = tmp;				\
		}							\
									\
		list->array[list->len - 1] = *elem;			\
		return 0;						\
	}

#define ARRAYLIST_FOREACH(list, cursor) for (				\
	cursor = (list)->array;						\
	(cursor - ((typeof(cursor)) ((list)->array))) < (list)->len;	\
	cursor++							\
)

#endif /* SRC_ARRAY_LIST_H_ */
