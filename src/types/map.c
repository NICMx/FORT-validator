#include "types/map.h"

#include <errno.h>

#include "alloc.h"
#include "common.h"
#include "config.h"
#include "log.h"
#include "rrdp.h"
#include "state.h"
#include "str_token.h"
#include "thread_var.h"
#include "cache/local_cache.h"
#include "config/filename_format.h"
#include "data_structure/path_builder.h"

/**
 * Aside from the reference counter, instances are meant to be immutable.
 *
 * TODO (fine) This structure is so intertwined with the cache module,
 * nowadays it feels like it should be moved there.
 */
struct cache_mapping {
	/**
	 * The one that always starts with "rsync://" or "https://".
	 * Normalized, ASCII-only, NULL-terminated.
	 */
	char *url;

	/**
	 * Cache location where we downloaded the file.
	 * Normalized, ASCII-only, NULL-terminated.
	 * Sometimes NULL, depending on @type.
	 */
	char *path;

	enum map_type type;

	unsigned int references; /* Reference counter */
};

/*
 * @character is an integer because we sometimes receive signed chars, and other
 * times we get unsigned chars.
 * Casting a negative char into a unsigned char is undefined behavior.
 */
static int
validate_url_character(int character)
{
	/*
	 * RFCs 1738 and 3986 define a very specific range of allowed
	 * characters, but I don't think we're that concerned about URL
	 * correctness. Validating the URL properly is more involved than simply
	 * checking legal characters, anyway.
	 *
	 * What I really need this validation for is ensure that we won't get
	 * any trouble later, when we attempt to map the URL to a path.
	 *
	 * Sample trouble: Getting UTF-8 characters. Why are they trouble?
	 * Because we don't have any guarantees that the system's file name
	 * encoding is UTF-8. URIs are not supposed to contain UTF-8 in the
	 * first place, so we have no reason to deal with encoding conversion.
	 *
	 * To be perfectly fair, we have no guarantees that the system's file
	 * name encoding is ASCII-compatible either, but I need to hang onto
	 * SOMETHING.
	 *
	 * (Asking users to use UTF-8 is fine, but asking users to use something
	 * ASCII-compatible is a little better.)
	 *
	 * So just make sure that the character is printable ASCII.
	 *
	 * TODO (next iteration) Consider exhaustive URL validation.
	 */
	return (0x20 <= character && character <= 0x7E)
	    ? 0
	    : pr_val_err("URL has non-printable character code '%d'.", character);
}

static int normalize_url(struct path_builder *, char const *, char const *, int);

/**
 * Initializes @map->url by building a normalized version of @str.
 */
static int
init_url(struct cache_mapping *map, char const *str)
{
	char const *s;
	char const *pfx;
	int error;
	struct path_builder pb;

	if (str == NULL){
		map->url = NULL;
		return 0;
	}

	for (s = str; s[0] != '\0'; s++) {
		error = validate_url_character(s[0]);
		if (error)
			return error;
	}

	pfx = NULL;
	error = 0;

	switch (map->type) {
	case MAP_RSYNC:
		pfx = "rsync://";
		error = ENOTRSYNC;
		break;
	case MAP_HTTP:
	case MAP_NOTIF:
		pfx = "https://";
		error = ENOTHTTPS;
		break;
	}

	if (pfx == NULL)
		pr_crit("Unknown mapping type: %u", map->type);

	__pb_init(&pb, RPKI_SCHEMA_LEN - 1);
	error = normalize_url(&pb, str, pfx, error);
	if (error) {
		pb_cleanup(&pb);
		return error;
	}

	map->url = strncpy(pb.string, str, RPKI_SCHEMA_LEN);
	return 0;
}

struct path_parser {
	char const *token;
	char const *slash;
	size_t len;
};

/* Return true if there's a new token, false if we're done. */
static bool
path_next(struct path_parser *parser)
{
	if (parser->slash == NULL)
		return false;

	parser->token = parser->slash + 1;
	parser->slash = strchr(parser->token, '/');
	parser->len = (parser->slash != NULL)
	    ? (parser->slash - parser->token)
	    : strlen(parser->token);

	return parser->token[0] != 0;
}

static bool
path_is_dot(struct path_parser *parser)
{
	return parser->len == 1 && parser->token[0] == '.';
}

static bool
path_is_dotdots(struct path_parser *parser)
{
	return parser->len == 2
	    && parser->token[0] == '.'
	    && parser->token[1] == '.';
}

static int
normalize_url(struct path_builder *pb, char const *url, char const *pfx,
    int errnot)
{
	struct path_parser parser;
	size_t dot_dot_limit;
	int error;

	/* Schema */
	if (!str_starts_with(url, pfx)) {
		pr_val_err("URL '%s' does not begin with '%s'.", url, pfx);
		return errnot;
	}

	/* Domain */
	parser.slash = url + 7;
	if (!path_next(&parser))
		return pr_val_err("URL '%s' seems to lack a domain.", url);
	if (path_is_dot(&parser)) {
		/* Dumping files to the cache root is unsafe. */
		return pr_val_err("URL '%s' employs the root domain. This is not really cacheable, so I'm going to distrust it.",
		    url);
	}
	if (path_is_dotdots(&parser)) {
		return pr_val_err("URL '%s' seems to be dot-dotting past its own schema.",
		    url);
	}
	error = pb_appendn(pb, parser.token, parser.len);
	if (error)
		return error;

	/* Other components */
	dot_dot_limit = pb->len;
	while (path_next(&parser)) {
		if (path_is_dotdots(&parser)) {
			error = pb_pop(pb, false);
			if (error)
				return error;
			if (pb->len < dot_dot_limit) {
				return pr_val_err("URL '%s' seems to be dot-dotting past its own domain.",
				    url);
			}
		} else if (!path_is_dot(&parser)) {
			error = pb_appendn(pb, parser.token, parser.len);
			if (error)
				return error;
		}
	}

	return 0;
}

/*
 * Maps "rsync://a.b.c/d/e.cer" into "<local-repository>/rsync/a.b.c/d/e.cer".
 */
static int
map_simple(struct cache_mapping *map, char const *subdir)
{
	struct path_builder pb;
	int error;

	error = pb_init_cache(&pb, subdir);
	if (error)
		return error;

	error = pb_append(&pb, &map->url[SCHEMA_LEN]);
	if (error) {
		pb_cleanup(&pb);
		return error;
	}

	map->path = pb.string;
	return 0;
}

static int
init_path(struct cache_mapping *map)
{
	switch (map->type) {
	case MAP_RSYNC:
		return map_simple(map, "rsync");
	case MAP_HTTP:
		return map_simple(map, "https");
	case MAP_NOTIF:
		return cache_tmpfile(&map->path);
	}

	pr_crit("Unknown URL type: %u", map->type);
	return -EINVAL; /* Unreachable */
}

int
map_create(struct cache_mapping **result, enum map_type type, char const *url)
{
	struct cache_mapping *map;
	int error;

	map = pmalloc(sizeof(struct cache_mapping));
	map->type = type;
	map->references = 1;

	error = init_url(map, url);
	if (error) {
		free(map);
		return error;
	}

	error = init_path(map);
	if (error) {
		free(map->url);
		free(map);
		return error;
	}

	*result = map;
	return 0;
}

/* Cache-only; url and type are meaningless. */
struct cache_mapping *
map_create_cache(char const *path)
{
	struct cache_mapping *map;

	map = pzalloc(sizeof(struct cache_mapping));
	map->path = pstrdup(path);
	map->references = 1;

	return map;
}

struct cache_mapping *
map_refget(struct cache_mapping *map)
{
	map->references++;
	return map;
}

void
map_refput(struct cache_mapping *map)
{
	if (map == NULL)
		return;

	map->references--;
	if (map->references == 0) {
		free(map->url);
		free(map->path);
		free(map);
	}
}

char const *
map_get_url(struct cache_mapping *map)
{
	return map->url;
}

char const *
map_get_path(struct cache_mapping *map)
{
	return map->path;
}

bool
map_equals(struct cache_mapping *m1, struct cache_mapping *m2)
{
	return strcmp(m1->url, m2->url) == 0;
}

bool
str_same_origin(char const *url1, char const *url2)
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

/* @ext must include the period. */
bool
map_has_extension(struct cache_mapping *map, char const *ext)
{
	return str_ends_with(map->url, ext);
}

enum map_type
map_get_type(struct cache_mapping *map)
{
	return map->type;
}

static char const *
get_filename(char const *file_path)
{
	char *slash = strrchr(file_path, '/');
	return (slash != NULL) ? (slash + 1) : file_path;
}

static char const *
map_get_printable(struct cache_mapping *map, enum filename_format format)
{
	switch (format) {
	case FNF_GLOBAL:
		return map->url;
	case FNF_LOCAL:
		return map->path;
	case FNF_NAME:
		return get_filename(map->url);
	}

	pr_crit("Unknown file name format: %u", format);
	return NULL;
}

char const *
map_val_get_printable(struct cache_mapping *map)
{
	enum filename_format format;

	format = config_get_val_log_filename_format();
	return map_get_printable(map, format);
}

char const *
map_op_get_printable(struct cache_mapping *map)
{
	enum filename_format format;

	format = config_get_op_log_filename_format();
	return map_get_printable(map, format);
}

DEFINE_ARRAY_LIST_FUNCTIONS(map_list, struct cache_mapping *, static)

void
maps_init(struct map_list *maps)
{
	map_list_init(maps);
}

static void
__map_refput(struct cache_mapping **map)
{
	map_refput(*map);
}

void
maps_cleanup(struct map_list *maps)
{
	map_list_cleanup(maps, __map_refput);
}

/* Swallows @map. */
void
maps_add(struct map_list *maps, struct cache_mapping *map)
{
	map_list_add(maps, &map);
}