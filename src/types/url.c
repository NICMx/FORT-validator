#include "types/url.h"

#include "alloc.h"
#include "data_structure/path_builder.h"

static char *
path_rewind(char const *root, char *cursor)
{
	for (cursor -= 2; root <= cursor; cursor--)
		if (*cursor == '/')
			return cursor + 1;
	return NULL;
}

/* Collapses '//' (after the schema), '.' and '..'. */
char *
url_normalize(char const *url)
{
	char *normal, *dst, *root;
	struct tokenizer tkn;

	if (strncmp(url, "rsync://", RPKI_SCHEMA_LEN) &&
	    strncmp(url, "https://", RPKI_SCHEMA_LEN))
		return NULL;

	normal = pstrdup(url);
	dst = normal + RPKI_SCHEMA_LEN;
	root = dst - 1;
	token_init(&tkn, url + RPKI_SCHEMA_LEN);

	while (token_next(&tkn)) {
		if (tkn.len == 1 && tkn.str[0] == '.')
			continue;
		if (tkn.len == 2 && tkn.str[0] == '.' && tkn.str[1] == '.') {
			dst = path_rewind(root, dst);
			if (!dst)
				goto fail;
			continue;
		}
		strncpy(dst, tkn.str, tkn.len);
		dst[tkn.len] = '/';
		dst += tkn.len + 1;
	}

	/* Reject URL if there's nothing after the schema. Maybe unnecessary. */
	if (dst == normal + RPKI_SCHEMA_LEN)
		goto fail;

	dst[-1] = '\0';
	return normal;

fail:	free(normal);
	return NULL;
}
