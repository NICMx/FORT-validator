#ifndef SRC_DATA_STRUCTURE_UTHASH_NONFATAL_H_
#define SRC_DATA_STRUCTURE_UTHASH_NONFATAL_H_

#include <errno.h>

/*
 * "To enable "returning a failure" if memory cannot be allocated, define the
 * macro HASH_NONFATAL_OOM before including the uthash.h header file."
 * (http://troydhanson.github.io/uthash/userguide.html#_out_of_memory)
 *
 * The errno variable will be set to ENOMEM, so that the caller can detect the
 * error.
 *
 * This validation (check for errno) must be done on ops that allocate memory,
 * so set 'errno' to 0 before this ops are made. The 'obj' won't be freed,
 * this is the caller's responsibility.
 *
 * Functions that can OOM:
 *
 * 	HASH_ADD_TO_TABLE
 * 		HASH_ADD_KEYPTR_BYHASHVALUE_INORDER
 * 			HASH_REPLACE_BYHASHVALUE_INORDER
 * 				HASH_REPLACE_INORDER
 * 			HASH_ADD_KEYPTR_INORDER
 * 				HASH_ADD_INORDER
 * 			HASH_ADD_BYHASHVALUE_INORDER
 * 		HASH_ADD_KEYPTR_BYHASHVALUE
 * 			HASH_REPLACE_BYHASHVALUE
 * 				HASH_REPLACE (*)
 * 					HASH_REPLACE_STR (**)
 * 					HASH_REPLACE_INT
 * 					HASH_REPLACE_PTR
 * 			HASH_ADD_KEYPTR
 * 				HASH_ADD
 * 			HASH_ADD_BYHASHVALUE
 * 	HASH_SELECT
 *
 * (*) Used by Fort
 * (**) Used by Fort, but only in its fatal uthash form.
 */
#define HASH_NONFATAL_OOM 1
#define uthash_nonfatal_oom(obj)					\
	errno = ENOMEM;							\

#include "data_structure/uthash.h"

#endif /* SRC_DATA_STRUCTURE_UTHASH_NONFATAL_H_ */
