#include "uri.h"

#include <errno.h>
#include "common.h"
#include "config.h"
#include "log.h"
#include "str.h"

/* Expected URI types */
enum rpki_uri_type {
	URI_RSYNC,
	URI_HTTPS,
};

/**
 * All rpki_uris are guaranteed to be RSYNC URLs right now.
 *
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
	 */
	char *local;
	/* "local_len" is never needed right now. */

	/* Type, currently rysnc and https are valid */
	enum rpki_uri_type type;

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
	    : pr_err("URL has non-printable character code '%d'.", character);
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

	uri->global = malloc(str_len + 1);
	if (uri->global == NULL)
		return pr_enomem();
	strncpy(uri->global, str, str_len);
	uri->global[str_len] = '\0';
	uri->global_len = str_len;

	return 0;
}

/**
 * Initializes @uri->global given manifest path @mft and its referenced file
 * @ia5.
 *
 * ie. if @mft is "rsync://a/b/c.mft" and @ia5 is "d/e/f.cer", @uri->global will
 * be "rsync://a/b/d/e/f.cer".
 *
 * Assumes that @mft is a "global" URL. (ie. extracted from rpki_uri.global.)
 */
static int
ia5str2global(struct rpki_uri *uri, char const *mft, IA5String_t *ia5)
{
	int error;
	size_t i;

	char *joined;
	char *slash_pos;
	int dir_len;

	/*
	 * IA5String is a subset of ASCII. However, IA5String_t doesn't seem to
	 * be guaranteed to be NULL-terminated.
	 * `(char *) ia5->buf` is fair, but `strlen(ia5->buf)` is not.
	 */

	for (i = 0; i < ia5->size; i++) {
		error = validate_url_character(ia5->buf[i]);
		if (error)
			return error;
	}

	slash_pos = strrchr(mft, '/');
	if (slash_pos == NULL) {
		joined = malloc(ia5->size + 1);
		if (!joined)
			return pr_enomem();
		strncpy(joined, (char *) ia5->buf, ia5->size);
		joined[ia5->size] = '\0';
		dir_len = 0;
		goto succeed;
	}

	dir_len = (slash_pos + 1) - mft;
	joined = malloc(dir_len + ia5->size + 1);
	if (!joined)
		return pr_enomem();

	strncpy(joined, mft, dir_len);
	strncpy(joined + dir_len, (char *) ia5->buf, ia5->size);
	joined[dir_len + ia5->size] = '\0';

succeed:
	uri->global = joined;
	uri->global_len = dir_len + ia5->size;
	return 0;
}

static int
validate_uri_begin(char const *uri_pfx, const size_t uri_pfx_len,
    char const *global, size_t global_len, size_t *size, int error)
{
	if (global_len < uri_pfx_len
	    || strncmp(uri_pfx, global, uri_pfx_len) != 0) {
		if (!error)
			return -EINVAL;
		pr_err("Global URI '%s' does not begin with '%s'.",
		    global, uri_pfx);
		return error;
	}

	(*size) = uri_pfx_len;
	return 0;
}

static int
validate_gprefix(char const *global, size_t global_len, uint8_t flags,
    size_t *size, enum rpki_uri_type *type)
{
	static char const *const PFX_RSYNC = "rsync://";
	static char const *const PFX_HTTPS = "https://";
	size_t const PFX_RSYNC_LEN = strlen(PFX_RSYNC);
	size_t const PFX_HTTPS_LEN = strlen(PFX_HTTPS);
	int error;

	if (flags == URI_VALID_RSYNC) {
		(*type) = URI_RSYNC;
		return validate_uri_begin(PFX_RSYNC, PFX_RSYNC_LEN, global,
		    global_len, size, ENOTRSYNC);
	}
	if (flags == URI_VALID_HTTPS) {
		(*type) = URI_HTTPS;
		return validate_uri_begin(PFX_HTTPS, PFX_HTTPS_LEN, global,
		    global_len, size, ENOTHTTPS);
	}
	if (flags != (URI_VALID_RSYNC & URI_VALID_HTTPS))
		pr_crit("Unknown URI flag");

	/* It has both flags */
	error = validate_uri_begin(PFX_RSYNC, PFX_RSYNC_LEN, global, global_len,
	    size, 0);
	if (!error) {
		(*type) = URI_RSYNC;
		return 0;
	}
	error = validate_uri_begin(PFX_HTTPS, PFX_HTTPS_LEN, global, global_len,
	    size, 0);
	if (error)
		return ENOTSUPPORTED;

	/* @size was already set */
	(*type) = URI_HTTPS;
	return 0;
}

/**
 * Initializes @uri->local by converting @uri->global.
 *
 * For example, given local cache repository "/tmp/rpki" and global uri
 * "rsync://rpki.ripe.net/repo/manifest.mft", initializes @uri->local as
 * "/tmp/rpki/rpki.ripe.net/repo/manifest.mft".
 *
 * By contract, if @guri is not RSYNC nor HTTPS, this will return ENOTRSYNC.
 * This often should not be treated as an error; please handle gracefully.
 */
static int
g2l(char const *global, size_t global_len, uint8_t flags, char **result,
    enum rpki_uri_type *result_type)
{
	char const *repository;
	char *local;
	size_t prefix_len;
	size_t repository_len;
	size_t extra_slash;
	size_t offset;
	enum rpki_uri_type type;
	int error;

	repository = config_get_local_repository();
	repository_len = strlen(repository);

	error = validate_gprefix(global, global_len, flags, &prefix_len, &type);
	if (error)
		return error;

	global += prefix_len;
	global_len -= prefix_len;
	extra_slash = (repository[repository_len - 1] == '/') ? 0 : 1;

	local = malloc(repository_len + extra_slash + global_len + 1);
	if (!local)
		return pr_enomem();

	offset = 0;
	strcpy(local + offset, repository);
	offset += repository_len;
	strncpy(local + offset, "/", extra_slash);
	offset += extra_slash;
	strncpy(local + offset, global, global_len);
	offset += global_len;
	local[offset] = '\0';

	*result = local;
	(*result_type) = type;
	return 0;
}

static int
autocomplete_local(struct rpki_uri *uri, uint8_t flags)
{
	return g2l(uri->global, uri->global_len, flags, &uri->local,
	    &uri->type);
}

static int
uri_create(struct rpki_uri **result, uint8_t flags, void const *guri,
    size_t guri_len)
{
	struct rpki_uri *uri;
	int error;

	uri = malloc(sizeof(struct rpki_uri));
	if (uri == NULL)
		return pr_enomem();

	error = str2global(guri, guri_len, uri);
	if (error) {
		free(uri);
		return error;
	}

	error = autocomplete_local(uri, flags);
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
uri_create_str(struct rpki_uri **uri, char const *guri, size_t guri_len)
{
	return uri_create(uri, URI_VALID_RSYNC, guri, guri_len);
}

/* A URI that can be rsync or https */
int
uri_create_mixed_str(struct rpki_uri **uri, char const *guri, size_t guri_len)
{
	return uri_create(uri, URI_VALID_RSYNC & URI_VALID_HTTPS, guri,
	    guri_len);
}

/*
 * Manifests URIs are a little special in that they are relative.
 */
int
uri_create_mft(struct rpki_uri **result, struct rpki_uri *mft, IA5String_t *ia5)
{
	struct rpki_uri *uri;
	int error;

	uri = malloc(sizeof(struct rpki_uri));
	if (uri == NULL)
		return pr_enomem();

	error = ia5str2global(uri, mft->global, ia5);
	if (error) {
		free(uri);
		return error;
	}

	error = autocomplete_local(uri, URI_VALID_RSYNC);
	if (error) {
		free(uri->global);
		free(uri);
		return error;
	}

	uri->references = 1;
	*result = uri;
	return 0;
}

/*
 * Create @uri from the @ad, validating that the uri is of type(s) indicated
 * at @flags (can be URI_VALID_RSYNC and/or URI_VALID_HTTPS)
 */
int
uri_create_ad(struct rpki_uri **uri, ACCESS_DESCRIPTION *ad, int flags)
{
	ASN1_STRING *asn1_string;
	int type;

	asn1_string = GENERAL_NAME_get0_value(ad->location, &type);

	/*
	 * RFC 6487: "This extension MUST have an instance of an
	 * AccessDescription with an accessMethod of id-ad-rpkiManifest, (...)
	 * with an rsync URI [RFC5781] form of accessLocation."
	 *
	 * Ehhhhhh. It's a little annoying in that it seems to be stucking more
	 * than one requirement in a single sentence, which I think is rather
	 * rare for an RFC. Normally they tend to hammer things more.
	 *
	 * Does it imply that the GeneralName CHOICE is constrained to type
	 * "uniformResourceIdentifier"? I guess so, though I don't see anything
	 * stopping a few of the other types from also being capable of storing
	 * URIs.
	 *
	 * Also, nobody seems to be using the other types, and handling them
	 * would be a titanic pain in the ass. So this is what I'm committing
	 * to.
	 */
	if (type != GEN_URI) {
		pr_err("Unknown GENERAL_NAME type: %d", type);
		return -ENOTSUPPORTED;
	}

	/*
	 * GEN_URI signals an IA5String.
	 * IA5String is a subset of ASCII, so this cast is safe.
	 * No guarantees of a NULL chara, though.
	 *
	 * TODO (testers) According to RFC 5280, accessLocation can be an IRI
	 * somehow converted into URI form. I don't think that's an issue
	 * because the RSYNC clone operation should not have performed the
	 * conversion, so we should be looking at precisely the IA5String
	 * directory our g2l version of @asn1_string should contain.
	 * But ask the testers to keep an eye on it anyway.
	 */
	return uri_create(uri, flags,
	    ASN1_STRING_get0_data(asn1_string),
	    ASN1_STRING_length(asn1_string));
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

bool
uri_is_rsync(struct rpki_uri *uri)
{
	return uri->type == URI_RSYNC;
}

static char const *
get_filename(char const *file_path)
{
	char *slash = strrchr(file_path, '/');
	return (slash != NULL) ? (slash + 1) : file_path;
}

char const *
uri_get_printable(struct rpki_uri *uri)
{
	enum filename_format format;

	format = config_get_filename_format();
	switch (format) {
	case FNF_GLOBAL:
		return uri->global;
	case FNF_LOCAL:
		return uri->local;
	case FNF_NAME:
		return get_filename(uri->global);
	}

	pr_crit("Unknown file name format: %u", format);
}
