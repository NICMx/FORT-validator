#include "data_structure/circular_indexer.h"

#include <stdlib.h>
#include "log.h"

void
arridx_init(struct circular_indexer *result, size_t len)
{
	result->indexes = NULL;
	result->first = len - 1;
	result->current = len - 1;
	result->top = 0;
	result->len = len;
	result->allow_another_lap = false;
}

void
arridx_cleanup(struct circular_indexer *indexer)
{
	if (indexer->indexes != NULL)
		free(indexer->indexes);
}

static struct circular_indexer_node *
get_node(struct circular_indexer *indexer, array_index index)
{
	return &indexer->indexes[index - indexer->top];
}

static struct circular_indexer_node *
get_current(struct circular_indexer *indexer)
{
	return get_node(indexer, indexer->current);
}

array_index *
arridx_first(struct circular_indexer *indexer)
{
	indexer->allow_another_lap = true;

	if (arridx_next(indexer) == NULL)
		return NULL;

	indexer->first = indexer->current;
	indexer->allow_another_lap = false;
	return &indexer->current;
}

array_index *
arridx_next(struct circular_indexer *indexer)
{
	array_index result;

	if (indexer->len == 0)
		return NULL;

	if (indexer->indexes == NULL) {
		result = indexer->current + 1;
		if ((result - indexer->top) == indexer->len)
			result = indexer->top;
	} else {
		result = get_current(indexer)->next;
	}

	if (result == indexer->first) {
		if (!indexer->allow_another_lap)
			return NULL;
		indexer->allow_another_lap = false;
	}

	indexer->current = result;
	return &indexer->current;
}

static int
initialize_indexes(struct circular_indexer *indexer)
{
	struct circular_indexer_node *array;
	size_t len;
	array_index i;

	len = indexer->len;
	array = calloc(len, sizeof(struct circular_indexer_node));
	if (array == NULL)
		return pr_enomem();

	array[0].previous = len - 1;
	if (len > 1) {
		array[0].next = 1;
		for (i = 1; i < len - 1; i++) {
			array[i].previous = i - 1;
			array[i].next = i + 1;
		}
		array[len - 1].previous = len - 2;
	}
	array[len - 1].next = 0;

	indexer->indexes = array;
	return 0;
}

int
arridx_remove(struct circular_indexer *indexer)
{
	struct circular_indexer_node *node;
	int error;

	if (indexer->len == 0) {
		/*
		 * BTW: This also means that calling code used this function
		 * outside of a loop, so double no cookies.
		 */
		return pr_crit("Attempting to remove an element from an empty circular array.");
	}

	if (indexer->indexes == NULL) {
		if (indexer->top == indexer->current) {
			indexer->top++;
			if (indexer->first == indexer->current) {
				indexer->first++;
				indexer->allow_another_lap = true;
			}
			goto success;
		}

		error = initialize_indexes(indexer);
		if (error)
			return error;
	}

	node = get_current(indexer);

	if (indexer->first == indexer->current) {
		indexer->first = node->next;
		indexer->allow_another_lap = true;
	}

	indexer->indexes[node->previous].next = node->next;
	indexer->indexes[node->next].previous = node->previous;

success:
	indexer->len--;
	return 0;
}
