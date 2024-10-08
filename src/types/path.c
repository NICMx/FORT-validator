#include "types/path.h"

#include <errno.h>

#include "alloc.h"
#include "config.h"
#include "log.h"

/* These are arbitrary; feel free to change them. */
#ifndef INITIAL_CAPACITY /* Unit tests want to override this */
#define INITIAL_CAPACITY 128u
#endif
#define MAX_CAPACITY 4096u

static bool
is_delimiter(char chara)
{
	return chara == '/' || chara == '\0';
}

void
token_init(struct tokenizer *tkn, char const *str)
{
	tkn->str = str;
	tkn->len = 0;
}

/* Like strtok_r(), but doesn't corrupt the string. */
bool
token_next(struct tokenizer *tkn)
{
	tkn->str += tkn->len;
	while (tkn->str[0] == '/')
		tkn->str++;
	if (tkn->str[0] == '\0')
		return false;
	for (tkn->len = 1; !is_delimiter(tkn->str[tkn->len]); tkn->len++)
		;
	return true;
}

char const *
path_filename(char const *path)
{
	char *slash = strrchr(path, '/');
	return slash ? (slash + 1) : path;
}

/*
 * Cannot return NULL.
 *
 * XXX I'm starting to use this more. Probably sanitize better.
 */
char *
path_join(char const *path1, char const *path2)
{
	// XXX needed?
	if (path1[0] == 0)
		return pstrdup(path2);
	if (path2 == NULL || path2[0] == 0)
		return pstrdup(path1);

	return path_njoin(path1, path2, strlen(path2));
}

char *
path_njoin(char const *p1, char const *p2, size_t p2len)
{
	size_t n;
	char *result;
	int written;

	n = strlen(p1) + p2len + 2;
	result = pmalloc(n);

	written = snprintf(result, n, "%s/%.*s", p1, (int) p2len, p2);
	if (written != n - 1)
		pr_crit("path_njoin: %zu %d %s %.*s",
		    n, written, p1, (int) p2len, p2);

	return result;
}
