#ifndef SRC_DATA_STRUCTURE_ARRAY_LIST_H_
#define SRC_DATA_STRUCTURE_ARRAY_LIST_H_

#include <errno.h>
#include <stdlib.h>
#include "log.h"
#include "data_structure/common.h"

#define DEFINE_ARRAY_LIST_STRUCT(name, elem_type)			\
	struct name {							\
		/** Unidimensional array. Initialized lazily. */	\
		elem_type *array;					\
		/** Number of elements in @array. */			\
		size_t len;						\
		/** Actual allocated slots in @array. */		\
		size_t capacity;					\
	}

#define DECLARE_ARRAY_LIST_FUNCTIONS(name, elem_type)			\
	void name##_init(struct name *);				\
	void name##_cleanup(struct name *, void (*cb)(elem_type *));	\
	int name##_add(struct name *list, elem_type *elem);

#define DEFINE_ARRAY_LIST_FUNCTIONS(name, elem_type, modifiers)		\
	modifiers void							\
	name##_init(struct name *list)					\
	{								\
		list->array = NULL;					\
		list->len = 0;						\
		list->capacity = 0;					\
	}								\
									\
	modifiers void							\
	name##_cleanup(struct name *list, void (*cb)(elem_type *))	\
	{								\
		array_index i;						\
		if (cb != NULL)						\
			for (i = 0; i < list->len; i++)			\
				cb(&list->array[i]);			\
		free(list->array);					\
	}								\
									\
	/* Will store a shallow copy, not @elem */			\
	modifiers int							\
	name##_add(struct name *list, elem_type *elem)			\
	{								\
		elem_type *tmp;						\
									\
		if (list->array == NULL) {				\
			list->capacity = 8;				\
			list->array = malloc(list->capacity		\
			    * sizeof(elem_type));			\
			if (list->array == NULL)			\
				return pr_enomem();			\
		}							\
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
	DEFINE_ARRAY_LIST_FUNCTIONS(name, elem_type, )

#define STATIC_ARRAY_LIST(name, elem_type)					\
	DEFINE_ARRAY_LIST_STRUCT(name, elem_type);			\
	DEFINE_ARRAY_LIST_FUNCTIONS(name, elem_type, static)

#define ARRAYLIST_FOREACH(list, node, index) for (			\
	(index) = 0, (node) = (list)->array;				\
	(index) < (list)->len;						\
	(index)++, (node)++						\
)

#endif /* SRC_DATA_STRUCTURE_ARRAY_LIST_H_ */
