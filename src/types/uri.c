#include "types/uri.h"

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
 * TODO (fine) Needs rebranding. AFAIK, RPKI does not impose significant
 * restrictions to regular URIs (except for schema, I guess), "global URI" is
 * pretty much tautologic, and "local URI" is a misnomer. (Because it doesn't
 * have anything to do with 'interpretation is independent of access'.)
 * I can't even remember if this nomenclature made sense at some point.
 * It's more of a mapping than a URI.
 *
 * TODO (fine) Also, this structure is so intertwined with the cache module,
 * nowadays it feels like it should be moved there.
 */
struct rpki_uri {
	/**
	 * "Global URI".
	 * The one that always starts with "rsync://" or "https://".
	 * Normalized, ASCII-only, NULL-terminated.
	 */
	char *global;

	/**
	 * "Local URI".
	 * The file pointed by @global, but cached in the local filesystem.
	 * Normalized, ASCII-only, NULL-terminated.
	 * Sometimes NULL, depending on @type.
	 */
	char *local;

	enum uri_type type;

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

static int append_guri(struct path_builder *, char const *, char const *,
    int, bool);

/**
 * Initializes @uri->global by building a normalized version of @str.
 */
static int
str2global(char const *str, struct rpki_uri *uri)
{
#define SCHEMA_LEN 8 /* strlen("rsync://"), strlen("https://") */

	char const *s;
	char const *pfx;
	int error;
	struct path_builder pb;

	if (str == NULL){
		uri->global = NULL;
		return 0;
	}

	for (s = str; s[0] != '\0'; s++) {
		error = validate_url_character(s[0]);
		if (error)
			return error;
	}

	pfx = NULL;
	error = 0;

	switch (uri->type) {
	case UT_TA_RSYNC:
	case UT_RPP:
	case UT_CAGED:
	case UT_AIA:
	case UT_SO:
	case UT_MFT:
		pfx = "rsync://";
		error = ENOTRSYNC;
		break;
	case UT_TA_HTTP:
	case UT_NOTIF:
	case UT_TMP:
		pfx = "https://";
		error = ENOTHTTPS;
		break;
	}

	if (pfx == NULL)
		pr_crit("Unknown URI type: %u", uri->type);

	__pb_init(&pb, SCHEMA_LEN - 1);
	error = append_guri(&pb, str, pfx, error, true);
	if (error) {
		pb_cleanup(&pb);
		return error;
	}

	uri->global = strncpy(pb.string, str, SCHEMA_LEN);
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

static int
get_rrdp_workspace(struct path_builder *pb, struct rpki_uri *notif)
{
	int error;

	error = pb_init_cache(pb, "rrdp");
	if (error)
		return error;

	error = pb_append(pb, &notif->global[SCHEMA_LEN]);
	if (error)
		pb_cleanup(pb);

	return error;
}

/*
 * Maps "rsync://a.b.c/d/e.cer" into "<local-repository>/rsync/a.b.c/d/e.cer".
 */
static int
map_simple(struct rpki_uri *uri, char const *subdir)
{
	struct path_builder pb;
	int error;

	error = pb_init_cache(&pb, subdir);
	if (error)
		return error;

	error = pb_append(&pb, &uri->global[SCHEMA_LEN]);
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
map_caged(struct rpki_uri *uri, struct rpki_uri *notif)
{
	struct path_builder pb;
	int error;

	error = get_rrdp_workspace(&pb, notif);
	if (error)
		return error;

	if (uri->global == NULL)
		goto success; /* Caller is only interested in the cage. */

	error = pb_append(&pb, &uri->global[SCHEMA_LEN]);
	if (error) {
		pb_cleanup(&pb);
		return error;
	}

success:
	uri->local = pb.string;
	return 0;
}

static int
autocomplete_local(struct rpki_uri *uri, struct rpki_uri *notif)
{
	switch (uri->type) {
	case UT_TA_RSYNC:
	case UT_RPP:
	case UT_MFT:
		return map_simple(uri, "rsync");

	case UT_TA_HTTP:
		return map_simple(uri, "https");

	case UT_NOTIF:
	case UT_TMP:
		return cache_tmpfile(&uri->local);

	case UT_CAGED:
		return map_caged(uri, notif);

	case UT_AIA:
	case UT_SO:
		uri->local = NULL;
		return 0;
	}

	pr_crit("Unknown URI type: %u", uri->type);
}

int
uri_create(struct rpki_uri **result, enum uri_type type, struct rpki_uri *notif,
	   char const *guri)
{
	struct rpki_uri *uri;
	int error;

	uri = pmalloc(sizeof(struct rpki_uri));
	uri->type = type;
	uri->references = 1;

	error = str2global(guri, uri);
	if (error) {
		free(uri);
		return error;
	}

	error = autocomplete_local(uri, notif);
	if (error) {
		free(uri->global);
		free(uri);
		return error;
	}

	*result = uri;
	return 0;
}

/*
 * Manifest fileList entries are a little special in that they're just file
 * names. This function will infer the rest of the URL.
 */
int
uri_create_mft(struct rpki_uri **result, struct rpki_uri *notif,
	       struct rpki_uri *mft, IA5String_t *ia5)
{
	struct rpki_uri *uri;
	int error;

	uri = pmalloc(sizeof(struct rpki_uri));
	uri->type = (notif == NULL) ? UT_RPP : UT_CAGED;
	uri->references = 1;

	error = ia5str2global(uri, mft->global, ia5);
	if (error) {
		free(uri);
		return error;
	}

	error = autocomplete_local(uri, notif);
	if (error) {
		free(uri->global);
		free(uri);
		return error;
	}

	*result = uri;
	return 0;
}

/* Cache-only; global URI and type are meaningless. */
struct rpki_uri *
uri_create_cache(char const *path)
{
	struct rpki_uri *uri;

	uri = pzalloc(sizeof(struct rpki_uri));
	uri->local = pstrdup(path);
	uri->references = 1;

	return uri;
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
	if (uri == NULL)
		return;

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

bool
uri_equals(struct rpki_uri *u1, struct rpki_uri *u2)
{
	return strcmp(u1->global, u2->global) == 0;
}

bool
str_same_origin(char const *g1, char const *g2)
{
	size_t c, slashes;

	slashes = 0;
	for (c = 0; g1[c] == g2[c]; c++) {
		switch (g1[c]) {
		case '/':
			slashes++;
			if (slashes == 3)
				return true;
			break;
		case '\0':
			return slashes == 2;
		}
	}

	if (g1[c] == '\0')
		return (slashes == 2) && g2[c] == '/';
	if (g2[c] == '\0')
		return (slashes == 2) && g1[c] == '/';

	return false;
}

bool
uri_same_origin(struct rpki_uri *u1, struct rpki_uri *u2)
{
	return str_same_origin(u1->global, u2->global);
}

/* @ext must include the period. */
bool
uri_has_extension(struct rpki_uri *uri, char const *ext)
{
	return str_ends_with(uri->global, ext);
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

char *
uri_get_rrdp_workspace(struct rpki_uri *notif)
{
	struct path_builder pb;
	return (get_rrdp_workspace(&pb, notif) == 0) ? pb.string : NULL;
}

DEFINE_ARRAY_LIST_FUNCTIONS(uri_list, struct rpki_uri *, static)

void
uris_init(struct uri_list *uris)
{
	uri_list_init(uris);
}

static void
__uri_refput(struct rpki_uri **uri)
{
	uri_refput(*uri);
}

void
uris_cleanup(struct uri_list *uris)
{
	uri_list_cleanup(uris, __uri_refput);
}

/* Swallows @uri. */
void
uris_add(struct uri_list *uris, struct rpki_uri *uri)
{
	uri_list_add(uris, &uri);
}
