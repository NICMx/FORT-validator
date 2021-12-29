#include "types/uri.h"

#include "file.h"
#include "log.h"
#include "random.h"
#include "thread_var.h"
#include "data_structure/array_list.h"
#include "data_structure/path_builder.h"
#include "http/http.h"
#include "rrdp/rrdp.h"
#include "rsync/rsync.h"

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
	 * (Global = The ones that always start with "rsync://" or "https://")
	 *
	 * These things are IA5-encoded, which means you're not bound to get
	 * non-ASCII characters.
	 */
	char *global;

	/**
	 * "Local URI".
	 * The file pointed by the @global string, but cached in the local
	 * filesystem.
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
	 */
	char *local;

	enum rpki_uri_type type;

	/* Reference counter. */
	unsigned int references;
};

/* Always steals ownership of @global. */
static struct rpki_uri *
__uri_create(char *global, enum rpki_uri_type type)
{
	struct rpki_uri *uri;

	uri = malloc(sizeof(struct rpki_uri));
	if (uri == NULL) {
		free(global);
		return NULL;
	}

	uri->global = global;
	uri->local = NULL;
	uri->type = type;
	uri->references = 1;
	return uri;
}

/* Always steals ownership of @global. */
int
uri_create(char *global, enum rpki_uri_type type, struct rpki_uri **result)
{
	struct rpki_uri *uri;
	struct path_builder path;
	int error;

	uri = __uri_create(global, type);
	if (uri == NULL)
		return pr_enomem();

	switch (type) {
	case URI_TYPE_VERSATILE:
	case URI_TYPE_RSYNC:
	case URI_TYPE_HTTP_SIMPLE:
		path_init(&path);
		path_append(&path, config_get_local_repository());
		path_append_url(&path, uri_get_global(uri));
		error = path_compile(&path, &uri->local);
		if (error) {
			uri_refput(uri);
			return error;
		}
		break;

	case URI_TYPE_HTTP_CAGED:
		pr_crit("Bad constructor for caged URI.");
		break;

	case URI_TYPE_VOID:
		break;
	}

	*result = uri;
	return 0;
}

/* Always steals ownership of @global. */
int
uri_create_caged(char *global, struct rpki_uri *notification,
    struct rpki_uri **result)
{
	struct rpki_uri *uri;
	struct path_builder path;
	int error;

	uri = __uri_create(global, URI_TYPE_HTTP_CAGED);
	if (uri == NULL)
		return pr_enomem();

	path_init(&path);
	path_append(&path, config_get_local_repository());
	path_append(&path, "caged");
	path_append_url(&path, uri_get_global(notification));
	path_append_url(&path, uri_get_global(uri));
	error = path_compile(&path, &uri->local);
	if (error) {
		uri_refput(uri);
		return error;
	}

	*result = uri;
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

static int
create_neighbor(char const *prefix, IA5String_t *suffix, char **result)
{
	struct path_builder path;
	path_init(&path);
	path_append_limited(&path, prefix, strrchr(prefix, '/') - prefix);
	path_append_limited(&path, (char *) suffix->buf, suffix->size);
	return path_compile(&path, result);
}

int
uri_create_mft(struct rpki_uri *mft, IA5String_t *file,
    struct rpki_uri **result)
{
	struct rpki_uri *uri;
	char *global;
	int error;

	error = validate_mft_file(file);
	if (error)
		return error;

	error = create_neighbor(uri_get_global(mft), file, &global);
	if (error)
		return error;

	uri = __uri_create(global, URI_TYPE_VOID);
	if (uri == NULL)
		return pr_enomem();

	error = create_neighbor(uri_get_local(mft), file, &uri->local);
	if (error) {
		uri_refput(uri);
		return error;
	}

	*result = uri;
	return 0;
}

void
uri_refget(struct rpki_uri *uri)
{
	uri->references++;
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

/*
 * This function only really makes sense during or after the file download.
 * Otherwise it'll just return the arbitrary first global.
 *
 * Note, if you're trying to print the URI, then you should most likely use
 * uri_*_get_printable() instead.
 */
char const *
uri_get_global(struct rpki_uri *uri)
{
	return uri->global;
}

/* Can return NULL. TODO (aaaa) Review callers. */
char const *
uri_get_local(struct rpki_uri *uri)
{
	return uri->local;
}

enum rpki_uri_type
uri_get_type(struct rpki_uri *uri)
{
	return uri->type;
}

/* @ext must include the period. */
bool
uri_has_extension(struct rpki_uri *uri, char const *ext)
{
	char const *global;
	size_t global_len;
	size_t ext_len;

	global = uri_get_global(uri);
	global_len = strlen(global);
	ext_len = strlen(ext);
	if (global_len < ext_len)
		return false;

	return strncmp(global + global_len - ext_len, ext, ext_len) == 0;
}

bool
uri_is_certificate(struct rpki_uri *uri)
{
	return uri_has_extension(uri, ".cer");
}

static char const *
get_file_name(struct rpki_uri *uri)
{
	char const *global, *slash;
	global = uri_get_global(uri);
	slash = strrchr(global, '/');
	return (slash == NULL) ? global : (slash + 1);
}

static char const *
uri_get_printable(struct rpki_uri *uri, enum filename_format format)
{
	switch (format) {
	case FNF_GLOBAL:
		return uri_get_global(uri);
	case FNF_LOCAL:
		return uri_get_local(uri);
	case FNF_NAME:
		return get_file_name(uri);
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
