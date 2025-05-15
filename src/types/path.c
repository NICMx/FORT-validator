#include "types/path.h"

#include <errno.h>

#include "alloc.h"
#include "config.h"
#include "log.h"
#include "types/str.h"

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

static void
trim_leading_slashes(struct sized_string *str)
{
	while (str->str[0] == '/') {
		str->str++;
		str->len--;
	}
}

static void
trim_trailing_slashes(struct sized_string *str)
{
	while (str->len > 1 && str->str[str->len - 1] == '/')
		str->len--;
}

/* Result needs cleanup, cannot return NULL. */
char *
path_join(char const *path1, char const *path2)
{
	struct sized_string p1;
	struct sized_string p2;
	size_t n;
	char *result;

	if (path1) {
		p1.str = path1;
		p1.len = strlen(path1);
		trim_trailing_slashes(&p1);
	} else {
		memset(&p1, 0, sizeof(p1));
	}

	if (path2) {
		p2.str = path2;
		p2.len = strlen(path2);
		trim_leading_slashes(&p2);
	} else {
		memset(&p2, 0, sizeof(p2));
	}

	if (p1.len == 0 && p2.len == 0)
		return pstrdup("");
	if (p1.len == 0 || p1.str[0] == '\0')
		return pstrndup(p2.str, p2.len);
	if (p2.len == 0 || p2.str[0] == '\0')
		return pstrndup(p1.str, p1.len);

	n = p1.len + p2.len + 2;
	result = pmalloc(n);

	memcpy(result, p1.str, p1.len);
	result[p1.len] = '/';
	memcpy(result + p1.len + 1, p2.str, p2.len);
	result[n - 1] = '\0';

	return result;
}
