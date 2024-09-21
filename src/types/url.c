#include "types/url.h"

#include "alloc.h"
#include "common.h"
#include "types/path.h"

bool
url_is_rsync(char const *url)
{
	return str_starts_with(url, "rsync://");
}

bool
url_is_https(char const *url)
{
	return str_starts_with(url, "https://");
}

/*
 * XXX use this:
 *
 *	for (s = str; s[0] != '\0'; s++) {
		error = validate_url_character(s[0]);
		if (error)
			return error;
	}
 *
 * @character is an integer because we sometimes receive signed chars, and other
 * times we get unsigned chars.
 * Casting a negative char into a unsigned char is undefined behavior.
 */
//static int
//validate_url_character(int character)
//{
//	/*
//	 * RFCs 1738 and 3986 define a very specific range of allowed
//	 * characters, but I don't think we're that concerned about URL
//	 * correctness. Validating the URL properly is more involved than simply
//	 * checking legal characters, anyway.
//	 *
//	 * What I really need this validation for is ensure that we won't get
//	 * any trouble later, when we attempt to map the URL to a path.
//	 *
//	 * Sample trouble: Getting UTF-8 characters. Why are they trouble?
//	 * Because we don't have any guarantees that the system's file name
//	 * encoding is UTF-8. URIs are not supposed to contain UTF-8 in the
//	 * first place, so we have no reason to deal with encoding conversion.
//	 *
//	 * To be perfectly fair, we have no guarantees that the system's file
//	 * name encoding is ASCII-compatible either, but I need to hang onto
//	 * SOMETHING.
//	 *
//	 * (Asking users to use UTF-8 is fine, but asking users to use something
//	 * ASCII-compatible is a little better.)
//	 *
//	 * So just make sure that the character is printable ASCII.
//	 *
//	 * TODO (next iteration) Consider exhaustive URL validation.
//	 */
//	return (0x20 <= character && character <= 0x7E)
//	    ? 0
//	    : pr_val_err("URL has non-printable character code '%d'.", character);
//}

static char *
path_rewind(char const *root, char *cursor)
{
	for (cursor -= 2; root <= cursor; cursor--)
		if (*cursor == '/')
			return cursor + 1;
	return NULL;
}

static bool
has_bad_prefix(char const *url)
{
	// XXX what happens if code expects one but url is the other
	if (strncmp(url, "rsync://", RPKI_SCHEMA_LEN) &&
	    strncmp(url, "https://", RPKI_SCHEMA_LEN))
		return true;

	/* Disallow the root domain */
	url += RPKI_SCHEMA_LEN;
	if (url[0] == '/')
		return true;
	if (url[0] == '.' && url[1] == '/')
		return true;

	// XXX read the standard and reject more bad URLs
	return false;
}

/*
 * Collapses '//' (except from the schema), '.' and '..'.
 *
 * "rsync://a.b/./c//.././/d/." -> "rsync://a.b/d"
 */
char *
url_normalize(char const *url)
{
	char *normal, *dst;
	struct tokenizer tkn;

	if (has_bad_prefix(url))
		return NULL;

	normal = pstrdup(url);
	dst = normal + RPKI_SCHEMA_LEN;
	token_init(&tkn, url + RPKI_SCHEMA_LEN);

	while (token_next(&tkn)) {
		if (tkn.len == 1 && tkn.str[0] == '.')
			continue;
		if (tkn.len == 2 && tkn.str[0] == '.' && tkn.str[1] == '.') {
			dst = path_rewind(normal + RPKI_SCHEMA_LEN, dst);
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

bool
url_same_origin(char const *url1, char const *url2)
{
	size_t c, slashes;

	slashes = 0;
	for (c = 0; url1[c] == url2[c]; c++) {
		switch (url1[c]) {
		case '/':
			slashes++;
			if (slashes == 3)
				return true;
			break;
		case '\0':
			return slashes == 2;
		}
	}

	if (url1[c] == '\0')
		return (slashes == 2) && url2[c] == '/';
	if (url2[c] == '\0')
		return (slashes == 2) && url1[c] == '/';

	return false;
}
