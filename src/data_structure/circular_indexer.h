#ifndef SRC_DATA_STRUCTURE_CIRCULAR_INDEXER_H_
#define SRC_DATA_STRUCTURE_CIRCULAR_INDEXER_H_

#include <stdbool.h>
#include "data_structure/common.h"

/*
 * What I call a "circular indexer" is a data structure meant to add *temporal*
 * efficient list-like operations to an already existing array.
 *
 * (The operations are O(1) removal and subsequent circular bidirectional
 * iteration. Of course however, creating the indexer is O(n).)
 *
 * In pragmatic terms, a "circular indexer" is an iterator-like thingy which
 * will keep returning removal-sensitive indexes that can be used to dereference
 * another array. It's called "circular" because the iteration will wrap
 * (although each foreach will stop after one lap.)
 *
 * It's designed to be used by the ROA tree. While computing deltas, it's useful
 * to keep removing elements, not only to efficiently prevent re-traversal of
 * already handled nodes, but also to naturally end up with a list of unused
 * nodes. At the same time, delta computing is not supposed to destroy the tree.
 */

struct circular_indexer_node {
	array_index previous;
	array_index next;
};

struct circular_indexer {
	/*
	 * This is the array where we store the links between the nodes.
	 *
	 * Will be initialized lazily, because most iterations and removals will
	 * actually require nothing more than the variables below, and we don't
	 * want to allocate.
	 *
	 * `indexes[i]` always corresponds to `other_array[i + top]`
	 */
	struct circular_indexer_node *indexes;

	/*
	 * This is the index of some valid element in @indexes. It's called
	 * "first" because iteration always begins at this element.
	 *
	 * In practice, the code is set up so this points to the successor of
	 * the element in which the last iteration was interrupted. This is
	 * because this element has a high chance of being the element that
	 * calling code is going to be looking up in the next loop.
	 */
	array_index first;
	/** Element the iteration is currently traversing. */
	array_index current;
	/**
	 * Index of the first element that hasn't been removed.
	 * For example, if @top is 10, then elements 0-9 have been removed,
	 * and 10-* still exist.
	 *
	 * This is a white box optimization. We know that calling code most
	 * often uses the circular indexer to compare two identical arrays, and
	 * that any identical elements need to be removed along.
	 *
	 * So, most of the time, @top is all that is needed, and we can postpone
	 * the initialization of @indexes to never.
	 */
	array_index top;

	/**
	 * Number of elements remaining. (ie. that haven't been removed.)
	 * (The length of @indexes is not stored because it's never needed.)
	 */
	size_t len;

	/**
	 * Iteration normally stops when @current reaches @first a second time.
	 * But when the first element is removed, @first now points to the next
	 * one, so @current will need to "touch" @first again.
	 *
	 * This member reminds us that iteration needs to continue the next time
	 * @current reaches @first.
	 */
	bool allow_another_lap;
};

/*
 * Types:
 * @indexer: pointer to the struct circular_indexer you want to iterate.
 * @i: pointer to array_index. You will have to dereference it to get the index
 * cursor.
 *
 * Every time you start a foreach, iteration will continue where the last one
 * stopped. (But will do another full lap.)
 */
#define ARRIDX_FOREACH(indexer, i) \
	for (i = arridx_first(indexer); i != NULL; i = arridx_next(indexer))

void arridx_init(struct circular_indexer *, size_t);
void arridx_cleanup(struct circular_indexer *);

array_index *arridx_first(struct circular_indexer *);
array_index *arridx_next(struct circular_indexer *);
/* Removes the *current* element. (You must be iterating.) */
int arridx_remove(struct circular_indexer *);

/* TODO remove me */
void arridx_print(char const *, struct circular_indexer *);

#endif /* SRC_DATA_STRUCTURE_CIRCULAR_INDEXER_H_ */
