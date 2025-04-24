#include "types/url.h"

#include <curl/curl.h>

#include "alloc.h"
#include "common.h"
#include "log.h"
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
 * @character is an integer because we sometimes receive signed chars, and other
 * times we get unsigned chars.
 * Casting a negative char into a unsigned char is undefined behavior.
 */
static int
validate_url_character(int character)
{
	return (0x20 <= character && character <= 0x7E)
	    ? 0
	    : pr_val_err("URL has non-printable character code '%d'.", character);
}

/* Not done by libcurl, apparently */
static int
validate_url_characters(char const *str)
{
	char const *s;
	int error;

	for (s = str; s[0] != '\0'; s++) {
		error = validate_url_character(s[0]);
		if (error)
			return error;
	}

	return 0;
}

/*
 * See RFC 3986. Basically, "rsync://%61.b/./c/.././%64/." -> "rsync://a.b/d"
 *
 * This is not actually a perfect normalization, because it's deferred to curl,
 * whose implementation is somewhat flawed (at least until version 8.12.1):
 * https://github.com/curl/curl/issues/16829
 *
 * On the other hand, since Fort 2 no longer maps URI paths to literal local
 * paths, all normalization does for us is prevent some theoretical redundant
 * downloading, so it might not even be that necessary.
 */
char *
url_normalize(char const *url)
{
	CURLU *curlu;
	char *curl_normal;
	char *normal;
	CURLUcode err;

	if (validate_url_characters(url))
		return NULL;

	curlu = curl_url();
	if (!curlu)
		enomem_panic();

	/* The flag is needed by rsync */
	err = curl_url_set(curlu, CURLUPART_URL, url, CURLU_NON_SUPPORT_SCHEME);
	if (err)
		goto einval;
	err = curl_url_get(curlu, CURLUPART_URL, &curl_normal, 0);
	if (err)
		goto einval;

	curl_url_cleanup(curlu);

	if (strncmp(curl_normal, "rsync://", RPKI_SCHEMA_LEN) &&
	    strncmp(curl_normal, "https://", RPKI_SCHEMA_LEN)) {
		curl_free(curl_normal);
		return NULL;
	}

	normal = pstrdup(curl_normal);
	curl_free(curl_normal);
	return normal;

einval:	pr_val_err("Error parsing URL: %s", curl_url_strerror(err));
	curl_url_cleanup(curlu);
	return NULL;
}

char *
url_parent(char const *child)
{
	char *slash = strrchr(child, '/');
	return (slash != NULL) ? pstrndup(child, slash - child) : NULL;
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
