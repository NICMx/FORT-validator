#include "cachetmp.h"

#include <stdatomic.h>
#include <stdio.h>

#include "log.h"
#include "types/path.h"

static atomic_uint file_counter;

/*
 * Returns (in @buf, which needs to length CACHE_TMPFILE_BUFLEN) a unique
 * temporary file name in the local cache.
 * Note, it's a name, and it's pretty much reserved. The file itself will not be
 * created.
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
		pr_crit("I ran out of temporal directories: %u", next);
}
