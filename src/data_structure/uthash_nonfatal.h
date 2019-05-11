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
 */
#define HASH_NONFATAL_OOM 1
#define uthash_nonfatal_oom(obj)					\
	errno = ENOMEM;							\

#include "data_structure/uthash.h"

#endif /* SRC_DATA_STRUCTURE_UTHASH_NONFATAL_H_ */
