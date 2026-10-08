#include "cachetmp.h"

#include <stdatomic.h>

#include "log.h"

static atomic_uint file_counter;

/*
 * Returns (in @buf, which needs to length CACHE_TMPFILE_BUFLEN) a unique
 * temporary file name in the local cache.
 * It's just a path name, and theoretically reserved for the caller.
 * The file itself will not be created.
 *
 * The file will not be automatically deleted when it is closed or the program
 * terminates.
 */
void
cache_tmpfile(char *buf)
{
	unsigned int next;
	int written;

	next = atomic_fetch_add(&file_counter, 1u);

	written = snprintf(buf, CACHE_TMPFILE_BUFLEN, CACHE_TMPDIR "/%X", next);
	if (written >= CACHE_TMPFILE_BUFLEN)
		pr_panic("I ran out of temporal directories: %u", next);
}
