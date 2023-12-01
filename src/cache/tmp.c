#include "cache/tmp.h"

#include <stdatomic.h>

#include "common.h"
#include "data_structure/path_builder.h"

static atomic_uint file_counter;

static int
pb_init_tmp(struct path_builder *pb)
{
	return pb_init_cache(pb, NULL, "tmp");
}

int
init_tmpdir(void)
{
	struct path_builder pb;
	int error;

	error = pb_init_tmp(&pb);
	if (error)
		return error;

	error = mkdir_p(pb.string, true);

	pb_cleanup(&pb);
	return error;
}

/*
 * Returns a unique temporary file name in the local cache.
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

	error = pb_init_tmp(&pb);
	if (error)
		return error;
	error = pb_append_u32(&pb, atomic_fetch_add(&file_counter, 1u));
	if (error)
		return error;

	*filename = pb.string;
	return 0;
}
