#ifndef SRC_DATA_STRUCTURE_ARRAY_LIST_H_
#define SRC_DATA_STRUCTURE_ARRAY_LIST_H_

#include "data_structure/common.h"
#include "log.h"

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
	void name##_add(struct name *list, elem_type *elem);

#define DEFINE_ARRAY_LIST_FUNCTIONS(name, elem_type, modifiers)		\
	modifiers void							\
	name##_init(struct name *list)					\
	{								\
		list->array = NULL;					\
		list->len = 0;						\
		list->capacity = 0;					\
	}								\
									\
	/* Call name##_init() again if you want to reuse the list. */	\
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
	modifiers void							\
	name##_add(struct name *list, elem_type *elem)			\
	{								\
		if (list->array == NULL) {				\
			list->capacity = 8;				\
			list->array = pmalloc(list->capacity		\
			    * sizeof(elem_type));			\
		}							\
									\
		list->len++;						\
		while (list->len >= list->capacity) {			\
			list->capacity *= 2;				\
			list->array = prealloc(list->array,		\
			    list->capacity * sizeof(elem_type));	\
		}							\
									\
		list->array[list->len - 1] = *elem;			\
	}

#define STATIC_ARRAY_LIST(name, elem_type)				\
	DEFINE_ARRAY_LIST_STRUCT(name, elem_type);			\
	DEFINE_ARRAY_LIST_FUNCTIONS(name, elem_type, static)

#define ARRAYLIST_FOREACH(list, node) for (				\
	(node) = (list)->array;						\
	(node) < (list)->array + (list)->len;				\
	(node)++							\
)

#define ARRAYLIST_FOREACH_IDX(list, index) for (			\
	(index) = 0;							\
	(index) < (list)->len;						\
	(index)++							\
)

#endif /* SRC_DATA_STRUCTURE_ARRAY_LIST_H_ */
