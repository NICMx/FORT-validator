#include "types/str.h"

void
strlist_init(struct strlist *list)
{
	list->array = NULL;
	list->len = 0;
	list->capacity = 0;
}

void
strlist_add(struct strlist *list, char *str)
{
	if (list->array == NULL) {
		list->capacity = 8;
		list->array = pmalloc(list->capacity * sizeof(char *));
	}

	list->len++;
	while (list->len >= list->capacity) {
		list->capacity *= 2;
		list->array = prealloc(list->array,
		    list->capacity * sizeof(char *));
	}

	list->array[list->len - 1] = str;
}

/* Call strlist_init() again if you want to reuse the list. */
void
strlist_cleanup(struct strlist *list)
{
	array_index i;
	for (i = 0; i < list->len; i++)
		free(list->array[i]);
	free(list->array);
}
