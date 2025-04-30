#include "types/uri.h"

#include <curl/curl.h>
#include <errno.h>

#include "alloc.h"
#include "common.h"
#include "log.h"
#include "types/path.h"

bool
uri_is_rsync(struct uri const *url)
{
	return str_starts_with(url->_str, "rsync://");
}

bool
uri_is_https(struct uri const *url)
{
	return str_starts_with(url->_str, "https://");
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
 * That said, since Fort 2 no longer maps URI paths to literal local paths, all
 * normalization does for us is prevent some theoretical redundant downloading,
 * so it's fine.
 */
static char *
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

int
uri_init(struct uri *url, char const *str)
{
	str = url_normalize(str);
	if (!str)
		return EINVAL;

	__URI_INIT(url, str);
	return 0;
}

/* @str must already be normalized. */
void
__uri_init(struct uri *url, char const *str, size_t len)
{
	url->_str = (char *)str;
	url->_len = len;
}

void
uri_copy(struct uri *dst, struct uri const *src)
{
	dst->_str = src->_str ? pstrdup(src->_str) : NULL;
	dst->_len = src->_len;
}

void
uri_cleanup(struct uri *url)
{
	free(url->_str);
	url->_str = NULL;
}

bool
uri_equals(struct uri const *u1, struct uri const *u2)
{
	return (u1->_len == u2->_len)
	    ? (memcmp(u1->_str, u2->_str, u1->_len) == 0)
	    : false;
}

bool
uri_has_extension(struct uri const *url, char const *ext)
{
	return strcmp(url->_str + url->_len - strlen(ext), ext) == 0;
}

/* Result is a shallow copy; do not clean. */
int
uri_parent(struct uri const *child, struct uri *parent)
{
	char *slash;

	slash = strrchr(child->_str, '/');
	if (slash == NULL)
		return EINVAL;

	parent->_str = child->_str;
	parent->_len = slash - child->_str;
	return 0;
}

bool
uri_same_origin(struct uri const *uri1, struct uri const *uri2)
{
	char const *str1, *str2;
	size_t c, slashes;

	str1 = uri1->_str;
	str2 = uri2->_str;
	slashes = 0;

	for (c = 0; str1[c] == str2[c]; c++) {
		switch (str1[c]) {
		case '/':
			slashes++;
			if (slashes == 3)
				return true;
			break;
		case '\0':
			return slashes == 2;
		}
	}

	if (str1[c] == '\0')
		return (slashes == 2) && str2[c] == '/';
	if (str2[c] == '\0')
		return (slashes == 2) && str1[c] == '/';

	return false;
}

void
uri_child(struct uri const *parent, char const *name, size_t len,
    struct uri *child)
{
	size_t slash;

	slash = parent->_str[parent->_len - 1] != '/';

	child->_len = parent->_len + slash + len;
	child->_str = pmalloc(child->_len + 1);
	strncpy(child->_str, parent->_str, parent->_len);
	if (slash)
		child->_str[parent->_len] = '/';
	strncpy(child->_str + parent->_len + slash, name, len);
	child->_str[child->_len] = '\0';
}

DEFINE_ARRAY_LIST_FUNCTIONS(uris, struct uri, )
