#include "cachetmp.h"

#include <stdatomic.h>
#include "types/path.h"

static atomic_uint file_counter;

/*
 * Returns a unique temporary file name in the local cache. Note, it's a name,
 * and it's pretty much reserved. The file itself will not be created.
 *
 * The file will not be automatically deleted when it is closed or the program
 * terminates.
 *
 * The name of the function is inherited from tmpfile(3).
 *
 * The resulting string needs to be released.
 */
int
cache_tmpfile(char **filename)
{
	struct path_builder pb;
	int error;

	error = pb_init_cache(&pb, CACHE_TMPDIR);
	if (error)
		return error;

	error = pb_append_u32(&pb, atomic_fetch_add(&file_counter, 1u));
	if (error) {
		pb_cleanup(&pb);
		return error;
	}

	*filename = pb.string;
	return 0;
}