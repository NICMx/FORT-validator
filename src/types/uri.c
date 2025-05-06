#include "types/uri.h"

#include <errno.h>

#include "alloc.h"
#include "common.h"
#include "log.h"
#include "types/path.h"

#define URI_ALLOW_UNKNOWN_SCHEME (1 << 1)

struct sized_string {
	char const *str;
	size_t len;
};

struct uri_buffer {
	char *dst;
	array_index d;
	size_t capacity;
};

struct schema_metadata {
	unsigned int default_port;
	bool allow_userinfo;
	bool allow_empty_host;
	bool allow_query;
	bool allow_fragment;
};

struct schema_metadata const HTTPS = {
	.default_port = 443,
	.allow_userinfo = false,
	.allow_empty_host = false,
	.allow_query = true,
	.allow_fragment = true,
};

struct schema_metadata const RSYNC = {
	.default_port = 873,
	.allow_userinfo = true,
	.allow_empty_host = true,
	.allow_query = false,
	.allow_fragment = false,
};

static bool
is_proto(struct sized_string *scheme, char const *proto)
{
	return strncasecmp(scheme->str, proto, scheme->len) == 0;
}

static struct schema_metadata const *
get_metadata(struct sized_string *scheme)
{
	if (scheme->len != 5)
		return NULL;

	if (is_proto(scheme, "https"))
		return &HTTPS;
	if (is_proto(scheme, "rsync"))
		return &RSYNC;

	return NULL;
}

static bool
is_lowercase(char chr)
{
	return 'a' <= chr && chr <= 'z';
}

static bool
is_uppercase(char chr)
{
	return 'A' <= chr && chr <= 'Z';
}

static bool
is_digit(char chr)
{
	return '0' <= chr && chr <= '9';
}

static bool
is_symbol(char chr, char const *symbols)
{
	for (; symbols[0] != '\0'; symbols++)
		if (chr == symbols[0])
			return true;
	return false;
}

static char
to_lowercase(char uppercase)
{
	return uppercase - ('A' - 'a');
}

static char
to_uppercase(char chr)
{
	return is_lowercase(chr) ? (chr + ('A' - 'a')) : chr;
}

static bool
invalid(char const *errmsg)
{
	printf("%s\n", errmsg);
	return false;
}

static void
approve_chara(struct uri_buffer *buf, char chr)
{
	if (buf->d >= buf->capacity) {
		/* It seems this is dead code. */
		buf->capacity += 16;
		buf->dst = prealloc(buf->dst, buf->capacity);
	}

	buf->dst[buf->d++] = chr;
}

static bool
collect_authority(char const *auth, char const **at, char const **colon,
    char const **end)
{
	*at = NULL;
	*colon = NULL;

	for (; true; auth++) {
		switch (auth[0]) {
		case '/':
		case '?':
		case '#':
		case '\0':
			*end = auth;
			return true;
		case '@':
			if ((*at) == NULL) {
				*colon = NULL; /* Was a password if not null */
				*at = auth;
			}
			break;
		case ':':
			*colon = auth;
			break;
		}
	}
}

static void
collect_path(char const *path, char const **end)
{
	for (; true; path++)
		if (path[0] == '\0' || path[0] == '?' || path[0] == '#') {
			*end = path;
			return;
		}
}

static void
collect_query(char const *query, char const **end)
{
	for (; true; query++)
		if (query[0] == '\0' || query[0] == '#') {
			*end = query;
			return;
		}
}

static void
collect_fragment(char const *fragment, char const **end)
{
	for (; true; fragment++)
		if (fragment[0] == '\0') {
			*end = fragment;
			return;
		}
}

static bool
normalize_scheme(struct uri_buffer *buf, struct sized_string *scheme)
{
	char chr;
	array_index c;

	if (scheme->len == 0)
		return invalid("Scheme seems empty.");

	chr = scheme->str[0];
	if (is_lowercase(chr))
		approve_chara(buf, chr);
	else if (is_uppercase(chr))
		approve_chara(buf, to_lowercase(chr));
	else
		return invalid("First character is not a letter.");

	for (c = 1; c < scheme->len; c++) {
		chr = scheme->str[c];
		if (is_lowercase(chr) || is_digit(chr) || is_symbol(chr, "+.-"))
			approve_chara(buf, chr);
		else if (is_uppercase(chr))
			approve_chara(buf, to_lowercase(chr));
		else
			return invalid("Schema character is not letter, digit, plus, period or hyphen.");
	}

	approve_chara(buf, ':');
	approve_chara(buf, '/');
	approve_chara(buf, '/');
	return true;
}

static bool
is_unreserved(char chr)
{
	return is_lowercase(chr)
	    || is_uppercase(chr)
	    || is_digit(chr)
	    || is_symbol(chr, "-._~");
}

static bool
is_subdelim(char chr)
{
	return is_symbol(chr, "!$&'()*+,;=");
}

static bool
char2hex(char chr, unsigned int *hex)
{
	if (is_digit(chr)) {
		*hex = chr - '0';
		return true;
	}
	if (is_uppercase(chr)) {
		*hex = chr - 'A' + 10;
		return true;
	}
	if (is_lowercase(chr)) {
		*hex = chr - 'a' + 10;
		return true;
	}

	printf("Invalid hex digit: %c\n", chr);
	return invalid("Invalid hexadecimal digit.");
}

static bool
approve_pct_encoded(struct uri_buffer *buf, struct sized_string *sstr,
    array_index *offset)
{
	array_index off;
	unsigned int hex1;
	unsigned int hex2;
	unsigned int val;

	off = *offset;

	if (sstr->len - off < 3)
		return invalid("Unterminated %-encoding.");

	if (!char2hex(sstr->str[off + 1], &hex1))
		return false;
	if (!char2hex(sstr->str[off + 2], &hex2))
		return false;

	val = (hex1 << 4) | hex2;

	if (is_unreserved(val)) {
		approve_chara(buf, val);
		*offset += 2;
		return true;
	}

	approve_chara(buf, '%');
	approve_chara(buf, to_uppercase(sstr->str[off + 1]));
	approve_chara(buf, to_uppercase(sstr->str[off + 2]));
	*offset += 2;
	return true;
}

static bool
handle_pchar(struct uri_buffer *buf, struct sized_string *sstr,
    array_index *offset)
{
	char chr = sstr->str[*offset];

	if (is_unreserved(chr))
		approve_chara(buf, chr);
	else if (chr == '%')
		approve_pct_encoded(buf, sstr, offset);
	else if (is_subdelim(chr))
		approve_chara(buf, chr);
	else if (chr == ':' || chr == '@')
		approve_chara(buf, chr);
	else
		return false;
	return true;
}

static bool
normalize_userinfo(struct uri_buffer *buf, struct sized_string *userinfo)
{
	array_index c;
	char chr;

	if (userinfo->len == 0)
		return true;

	for (c = 0; c < userinfo->len; c++) {
		chr = userinfo->str[c];
		if (is_unreserved(chr))
			approve_chara(buf, chr);
		else if (chr == '%') {
			if (!approve_pct_encoded(buf, userinfo, &c))
				return false;
		} else if (is_subdelim(chr))
			approve_chara(buf, chr);
		else if (chr == ':')
			approve_chara(buf, chr);
		else
			return invalid("Illegal character in userinfo section.");
	}

	approve_chara(buf, '@');
	return true;
}

static bool
normalize_host(struct uri_buffer *buf, struct sized_string *host)
{
	array_index c;
	char chr;

	for (c = 0; c < host->len; c++) {
		chr = host->str[c];
		if (is_uppercase(chr))
			approve_chara(buf, to_lowercase(chr));
		else if (is_unreserved(chr))
			approve_chara(buf, chr);
		else if (chr == '%') {
			if (!approve_pct_encoded(buf, host, &c))
				return false;
		} else if (is_subdelim(chr))
			approve_chara(buf, chr);
		else
			return invalid("Illegal character in host section.");
	}

	return true;
}

static bool
normalize_port(struct uri_buffer *buf, struct sized_string *port,
    struct schema_metadata const *schema)
{
	array_index c;
	char chr;
	unsigned int portnum;

	if (port->len == 0)
		return true;

	portnum = 0;
	for (c = 0; c < port->len; c++) {
		chr = port->str[c];
		if (!is_digit(chr))
			return invalid("Illegal non-digit character in port section.");
		portnum = 10 * portnum + (chr - '0');
		if (portnum > 0xFFFF)
			return invalid("Port value is too large.");
	}

	if (schema && (portnum == schema->default_port))
		return true;

	approve_chara(buf, ':');
	for (c = 0; c < port->len; c++)
		approve_chara(buf, port->str[c]);
	return true;
}

static char const *
strnchr(char const *str, size_t n, char chr)
{
	array_index s;
	for (s = 0; s < n; s++)
		if (str[s] == chr)
			break;
	return str + s;
}

static bool
next_segment(struct sized_string *path, struct sized_string *segment)
{
	segment->str += segment->len + 1;
	if (segment->str > (path->str + path->len))
		return false;
	segment->len = strnchr(segment->str,
	    path->len - (segment->str - path->str),
	    '/') - segment->str;
	return true;
}

static void
rewind_buffer(struct uri_buffer *buf, size_t limit)
{
	while ((buf->d > limit) && (buf->dst[--buf->d] != '/'))
		;
}

static bool
normalize_path(struct uri_buffer *buf, struct sized_string *path)
{
	struct sized_string segment;
	array_index i;
	char chr;
	size_t limit;

	if (path->len == 0) {
		approve_chara(buf, '/');
		return true;
	}

	segment.str = path->str;
	segment.len = 0;
	limit = buf->d;

	while (next_segment(path, &segment)) {
		approve_chara(buf, '/');
		for (i = 0; i < segment.len; i++) {
			chr = segment.str[i];
			if (is_unreserved(chr))
				approve_chara(buf, chr);
			else if (chr == '%') {
				if (!approve_pct_encoded(buf, &segment, &i))
					return false;
			} else if (is_subdelim(chr) || is_symbol(chr, ":@"))
				approve_chara(buf, chr);
			else
				return invalid("Illegal character in path section.");
		}

		if (buf->dst[buf->d - 2] == '/' &&
		    buf->dst[buf->d - 1] == '.')
			rewind_buffer(buf, limit);
		if (buf->dst[buf->d - 3] == '/' &&
		    buf->dst[buf->d - 2] == '.' &&
		    buf->dst[buf->d - 1] == '.') {
			rewind_buffer(buf, limit);
			rewind_buffer(buf, limit);
		}
	}

	if (limit == buf->d)
		approve_chara(buf, '/');
	return true;
}

static bool
normalize_post_path(struct uri_buffer *buf, struct sized_string *post,
    char prefix)
{
	array_index c;
	char chr;

	if (post->len == 0)
		return true;

	approve_chara(buf, prefix);
	for (c = 1; c < post->len; c++) {
		if (handle_pchar(buf, post, &c))
			continue;
		chr = post->str[c];
		if (chr == ':' || chr == '@')
			approve_chara(buf, chr);
		else
			return invalid("Illegal character in query section.");
	}

	return true;
}

/*
 * See RFC 3986. Basically, "rsync://%61.b/./c/.././%64/." -> "rsync://a.b/d"
 */
static char *
url_normalize(char const *url, int flags)
{
	struct sized_string scheme;
	struct sized_string authority;
	struct sized_string userinfo;
	struct sized_string host;
	struct sized_string port;
	struct sized_string path;
	struct sized_string query;
	struct sized_string fragment;

	char const *cursor;
	char const *at;
	char const *colon;

	struct schema_metadata const *meta;
	struct uri_buffer buf;

	pr_clutter("-----------------------");
	pr_clutter("input: %s", url);

	cursor = strchr(url, ':');
	if (!cursor) {
		printf("Schema not terminated\n");
		return NULL;
	}

	scheme.str = url;
	scheme.len = cursor - url;
	pr_clutter("  scheme: %.*s (len:%zu)", (int)scheme.len, scheme.str, scheme.len);
	meta = get_metadata(&scheme);
	if (!(flags & URI_ALLOW_UNKNOWN_SCHEME) && !meta) {
		printf("Unknown scheme\n");
		return NULL;
	}

	if (cursor[1] != '/' || cursor[2] != '/') {
		printf("Missing \"://\"\n");
		return NULL;
	}

	authority.str = cursor + 3;
	if (!collect_authority(authority.str, &at, &colon, &cursor))
		return NULL;
	authority.len = cursor - authority.str;
	pr_clutter("  authority: %.*s (len:%zu)", (int)authority.len, authority.str, authority.len);
	if (authority.len == 0)
		return NULL;

	if (at != NULL) {
		if (meta && !meta->allow_userinfo) {
			printf("Protocol disallows userinfo.\n");
			return NULL;
		}

		userinfo.str = authority.str;
		userinfo.len = at - authority.str;
		host.str = at + 1;
	} else {
		userinfo.str = NULL;
		userinfo.len = 0;
		host.str = authority.str;
	}

	if (colon != NULL) {
		host.len = colon - host.str;
		port.str = colon + 1;
		port.len = cursor - port.str;
	} else {
		host.len = cursor - host.str;
		port.str = NULL;
		port.len = 0;
	}

	if (host.len == 0 && meta && !meta->allow_empty_host) {
		printf("Protocol disallows empty host.\n");
		return NULL;
	}

	pr_clutter("  userinfo: %.*s (len:%zu)", (int)userinfo.len, userinfo.str, userinfo.len);
	pr_clutter("  host: %.*s (len:%zu)", (int)host.len, host.str, host.len);
	pr_clutter("  port: %.*s (len:%zu)", (int)port.len, port.str, port.len);

	if (cursor[0] == '\0') {
		memset(&path, 0, sizeof(path));
		memset(&query, 0, sizeof(query));
		memset(&fragment, 0, sizeof(fragment));

	} else { /* '/' */
		path.str = cursor;
		collect_path(path.str, &cursor);
		path.len = cursor - path.str;

		switch (cursor[0]) {
		case '\0':
			memset(&query, 0, sizeof(query));
			memset(&fragment, 0, sizeof(fragment));
			break;

		case '?':
			if (meta && !meta->allow_query) {
				printf("Protocol disallows query.\n");
				return NULL;
			}

			query.str = cursor;
			collect_query(query.str + 1, &cursor);
			query.len = cursor - query.str;
			switch (cursor[0]) {
			case '\0':
				memset(&fragment, 0, sizeof(fragment));
				break;
			case '#':
				goto frag;
			default:
				pr_crit("Unhandled character after query: %c",
				    cursor[0]);
			}
			break;

		case '#':
			memset(&query, 0, sizeof(query));

frag:			if (meta && !meta->allow_fragment) {
				printf("Protocol disallows fragment.\n");
				return NULL;
			}
			fragment.str = cursor;
			collect_fragment(fragment.str + 1, &cursor);
			fragment.len = cursor - fragment.str;
			break;

		default:
			pr_crit("Unhandled character after path: %c",
			    cursor[0]);
		}
	}

	pr_clutter("  path: %.*s (len:%zu)", (int)path.len, path.str, path.len);
	pr_clutter("  query: %.*s (len:%zu)", (int)query.len, query.str, query.len);
	pr_clutter("  fragment: %.*s (len:%zu)", (int)fragment.len, fragment.str, fragment.len);

	buf.capacity = scheme.len + authority.len + path.len
	    + query.len + fragment.len + 5; /* "://" + maybe '/' + '\0' */
	buf.dst = pmalloc(buf.capacity);
	buf.d = 0;

	pr_clutter("-> Normalizing scheme.");
	if (!normalize_scheme(&buf, &scheme))
		goto cancel;
	pr_clutter("-> Normalizing userinfo.");
	if (!normalize_userinfo(&buf, &userinfo))
		goto cancel;
	pr_clutter("-> Normalizing host.");
	if (!normalize_host(&buf, &host))
		goto cancel;
	pr_clutter("-> Normalizing port.");
	if (!normalize_port(&buf, &port, meta))
		goto cancel;
	pr_clutter("-> Normalizing path.");
	if (!normalize_path(&buf, &path))
		goto cancel;
	pr_clutter("-> Normalizing query.");
	if (!normalize_post_path(&buf, &query, '?'))
		goto cancel;
	pr_clutter("-> Normalizing fragment.");
	if (!normalize_post_path(&buf, &fragment, '#'))
		goto cancel;

	approve_chara(&buf, '\0');
	return buf.dst;

cancel:	free(buf.dst);
	return NULL;
}

int
uri_init(struct uri *url, char const *str)
{
	char *normal;

	normal = url_normalize(str, 0);
	if (!normal)
		return EINVAL;

	__URI_INIT(url, normal);

	if (!uri_is_https(url) && !uri_is_rsync(url)) {
		free(normal);
		return ENOTSUP;
	}

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
uri_is_rsync(struct uri const *url)
{
	return str_starts_with(url->_str, "rsync:");
}

bool
uri_is_https(struct uri const *url)
{
	return str_starts_with(url->_str, "https:");
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

DEFINE_ARRAY_LIST_FUNCTIONS(uris, struct uri, )
