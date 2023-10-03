#include "types/uri.h"

#include "alloc.h"
#include "common.h"
#include "config.h"
#include "log.h"
#include "state.h"
#include "str_token.h"
#include "thread_var.h"
#include "config/filename_format.h"
#include "data_structure/path_builder.h"

/**
 * Design notes:
 *
 * Because we need to generate @local from @global, @global's allowed character
 * set must be a subset of @local. Because this is Unix, @local must never
 * contain NULL (except as a terminating character). Therefore, even though IA5
 * allows NULL, @global won't.
 *
 * Because we will simply embed @global (minus "rsync://") into @local, @local's
 * encoding must be IA5-compatible. In other words, UTF-16 and UTF-32 are out of
 * the question.
 *
 * Aside from the reference counter, instances are meant to be immutable.
 */
struct rpki_uri {
	/**
	 * "Global URI".
	 * The one that always starts with "rsync://" or "https://".
	 *
	 * These things are IA5-encoded, which means you're not bound to get
	 * non-ASCII characters.
	 */
	char *global;
	/** Length of @global. */
	size_t global_len;

	/**
	 * "Local URI".
	 * The file pointed by @global, but cached in the local filesystem.
	 *
	 * I can't find a standard that defines this, but lots of complaints on
	 * the Internet imply that Unix file paths are specifically meant to be
	 * C strings.
	 *
	 * So just to clarify: This is a string that permits all characters,
	 * printable or otherwise, except \0. (Because that's the terminating
	 * character.)
	 *
	 * Even though it might contain characters that are non-printable
	 * according to ASCII, we assume that we can just dump it into the
	 * output without trouble, because the input should have the same
	 * encoding as the output.
	 *
	 * Technically, "global" URI "https://a.b.c/d/..///./d" is not the same
	 * identifier as "https://a.b.c/d", but since we're supposed to download
	 * to a filesystem where "https/a.b.c/d" is the same file as
	 * "https/a.b.c/d/..///./d", @local will always be normalized.
	 */
	char *local;
	/* "local_len" is never needed right now. */

	enum uri_type type;

	unsigned int references;
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
	 * any trouble later, when we attempt to convert the global URI to a
	 * local file.
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

/**
 * Initializes @uri->global* by cloning @str.
 * This function does not assume that @str is null-terminated.
 */
static int
str2global(char const *str, size_t str_len, struct rpki_uri *uri)
{
	int error;
	size_t i;

	for (i = 0; i < str_len; i++) {
		error = validate_url_character(str[i]);
		if (error)
			return error;
	}

	uri->global = pmalloc(str_len + 1);
	strncpy(uri->global, str, str_len);
	uri->global[str_len] = '\0';
	uri->global_len = str_len;

	return 0;
}

static bool
is_valid_mft_file_chara(uint8_t chara)
{
	return ('a' <= chara && chara <= 'z')
	    || ('A' <= chara && chara <= 'Z')
	    || ('0' <= chara && chara <= '9')
	    || (chara == '-')
	    || (chara == '_');
}

/* RFC 6486bis, section 4.2.2 */
static int
validate_mft_file(IA5String_t *ia5)
{
	size_t dot;
	size_t i;

	if (ia5->size < 5)
		return pr_val_err("File name is too short (%zu < 5).", ia5->size);
	dot = ia5->size - 4;
	if (ia5->buf[dot] != '.')
		return pr_val_err("File name seems to lack a three-letter extension.");

	for (i = 0; i < ia5->size; i++) {
		if (i != dot && !is_valid_mft_file_chara(ia5->buf[i])) {
			return pr_val_err("File name contains illegal character #%u",
			    ia5->buf[i]);
		}
	}

	/*
	 * Actual extension doesn't matter; if there's no handler,
	 * we'll naturally ignore the file.
	 */
	return 0;
}

/**
 * Initializes @uri->global given manifest path @mft and its referenced file
 * @ia5.
 *
 * ie. if @mft is "rsync://a/b/c.mft" and @ia5 is "d.cer", @uri->global will
 * be "rsync://a/b/d.cer".
 *
 * Assumes that @mft is a "global" URL. (ie. extracted from rpki_uri.global.)
 */
static int
ia5str2global(struct rpki_uri *uri, char const *mft, IA5String_t *ia5)
{
	char *joined;
	char const *slash_pos;
	int dir_len;
	int error;

	/*
	 * IA5String is a subset of ASCII. However, IA5String_t doesn't seem to
	 * be guaranteed to be NULL-terminated.
	 * `(char *) ia5->buf` is fair, but `strlen(ia5->buf)` is not.
	 */

	error = validate_mft_file(ia5);
	if (error)
		return error;

	slash_pos = strrchr(mft, '/');
	if (slash_pos == NULL)
		return pr_val_err("Manifest URL '%s' contains no slashes.", mft);

	dir_len = (slash_pos + 1) - mft;
	joined = pmalloc(dir_len + ia5->size + 1);

	strncpy(joined, mft, dir_len);
	strncpy(joined + dir_len, (char *) ia5->buf, ia5->size);
	joined[dir_len + ia5->size] = '\0';

	uri->global = joined;
	uri->global_len = dir_len + ia5->size;
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
	    && parser->token[1] == '.' ;
}

static int
append_guri(struct path_builder *pb, char const *guri, char const *gprefix,
    int err, bool skip_schema)
{
	struct path_parser parser;
	size_t dot_dot_limit;
	int error;

	/* Schema */
	if (!str_starts_with(guri, gprefix)) {
		pr_val_err("URI '%s' does not begin with '%s'.", guri, gprefix);
		return err;
	}

	if (!skip_schema) {
		error = pb_appendn(pb, guri, 5);
		if (error)
			return error;
	}

	/* Domain */
	parser.slash = guri + 7;
	if (!path_next(&parser))
		return pr_val_err("URI '%s' seems to lack a domain.", guri);
	if (path_is_dot(&parser)) {
		/* Dumping files to the cache root is unsafe. */
		return pr_val_err("URI '%s' employs the root domain. This is not really cacheable, so I'm going to distrust it.",
		    guri);
	}
	if (path_is_dotdots(&parser)) {
		return pr_val_err("URI '%s' seems to be dot-dotting past its own schema.",
		    guri);
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
				return pr_val_err("URI '%s' seems to be dot-dotting past its own domain.",
				    guri);
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
map_simple(struct rpki_uri *uri, char const *gprefix, int err)
{
	struct path_builder pb;
	int error;

	pb_init(&pb);
	error = append_guri(&pb, uri->global, gprefix, err, false);
	if (error) {
		pb_cleanup(&pb);
		return error;
	}

	uri->local = pb.string;
	return 0;
}

/*
 * Maps "rsync://a.b.c/d/e.cer" into
 * "<local-repository>/rrdp/<notification-path>/a.b.c/d/e.cer".
 */
static int
map_caged(struct rpki_uri *uri)
{
	struct path_builder pb;
	struct rpki_uri *notification;
	int error;

	notification = validation_get_notification_uri(state_retrieve());
	if (notification == NULL)
		pr_crit("Programming error: Notification not recorded.");

	pb_init(&pb);

	error = pb_append(&pb, "rrdp");
	if (error)
		return error;
	error = append_guri(&pb, notification->global, "https://", ENOTHTTPS, true);
	if (error)
		return error;
	error = append_guri(&pb, uri->global, "rsync://", ENOTRSYNC, true);
	if (error)
		return error;

	uri->local = pb.string;
	return 0;
}

static int
autocomplete_local(struct rpki_uri *uri)
{
	switch (uri->type) {
	case UT_RSYNC:
		return map_simple(uri, "rsync://", ENOTRSYNC);
	case UT_HTTPS:
		return map_simple(uri, "https://", ENOTHTTPS);
	case UT_CAGED:
		return map_caged(uri);
	}

	pr_crit("Unknown URI type: %u", uri->type);
}

/*
 * I think the reason why @guri is not a char * is to convey that it doesn't
 * need to be NULL terminated, but I'm not sure.
 */
int
__uri_create(struct rpki_uri **result, enum uri_type type, void const *guri,
    size_t guri_len)
{
	struct rpki_uri *uri;
	int error;

	uri = pmalloc(sizeof(struct rpki_uri));

	error = str2global(guri, guri_len, uri);
	if (error) {
		free(uri);
		return error;
	}

	uri->type = type;

	error = autocomplete_local(uri);
	if (error) {
		free(uri->global);
		free(uri);
		return error;
	}

	uri->references = 1;

	*result = uri;
	return 0;
}

int
uri_create(struct rpki_uri **result, enum uri_type type, char const *guri)
{
	return __uri_create(result, type, guri, strlen(guri));
}

/*
 * Manifest fileList entries are a little special in that they're just file
 * names. This function will infer the rest of the URL.
 */
int
uri_create_mft(struct rpki_uri **result, struct rpki_uri *mft, IA5String_t *ia5)
{
	struct rpki_uri *uri;
	int error;

	uri = pmalloc(sizeof(struct rpki_uri));

	error = ia5str2global(uri, mft->global, ia5);
	if (error) {
		free(uri);
		return error;
	}

	uri->type = UT_RSYNC;

	error = autocomplete_local(uri);
	if (error) {
		free(uri->global);
		free(uri);
		return error;
	}

	uri->references = 1;

	*result = uri;
	return 0;
}

struct rpki_uri *
uri_refget(struct rpki_uri *uri)
{
	uri->references++;
	return uri;
}

void
uri_refput(struct rpki_uri *uri)
{
	uri->references--;
	if (uri->references == 0) {
		free(uri->global);
		free(uri->local);
		free(uri);
	}
}

char const *
uri_get_global(struct rpki_uri *uri)
{
	return uri->global;
}

char const *
uri_get_local(struct rpki_uri *uri)
{
	return uri->local;
}

size_t
uri_get_global_len(struct rpki_uri *uri)
{
	return uri->global_len;
}

bool
uri_equals(struct rpki_uri *u1, struct rpki_uri *u2)
{
	return strcmp(u1->global, u2->global) == 0;
}

/* @ext must include the period. */
bool
uri_has_extension(struct rpki_uri *uri, char const *ext)
{
	size_t ext_len;
	int cmp;

	ext_len = strlen(ext);
	if (uri->global_len < ext_len)
		return false;

	cmp = strncmp(uri->global + uri->global_len - ext_len, ext, ext_len);
	return cmp == 0;
}

bool
uri_is_certificate(struct rpki_uri *uri)
{
	return uri_has_extension(uri, ".cer");
}

enum uri_type
uri_get_type(struct rpki_uri *uri)
{
	return uri->type;
}

bool
uri_is_rsync(struct rpki_uri *uri)
{
	return uri->type == UT_RSYNC;
}

bool
uri_is_https(struct rpki_uri *uri)
{
	return uri->type == UT_HTTPS;
}

static char const *
get_filename(char const *file_path)
{
	char *slash = strrchr(file_path, '/');
	return (slash != NULL) ? (slash + 1) : file_path;
}

static char const *
uri_get_printable(struct rpki_uri *uri, enum filename_format format)
{
	switch (format) {
	case FNF_GLOBAL:
		return uri->global;
	case FNF_LOCAL:
		return uri->local;
	case FNF_NAME:
		return get_filename(uri->global);
	}

	pr_crit("Unknown file name format: %u", format);
	return NULL;
}

char const *
uri_val_get_printable(struct rpki_uri *uri)
{
	enum filename_format format;

	format = config_get_val_log_filename_format();
	return uri_get_printable(uri, format);
}

char const *
uri_op_get_printable(struct rpki_uri *uri)
{
	enum filename_format format;

	format = config_get_op_log_filename_format();
	return uri_get_printable(uri, format);
}
