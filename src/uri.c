#include "uri.h"

#include "common.h"
#include "log.h"

/**
 * Initializes @uri->global* by cloning @str.
 * This function does not assume that @str is null-terminated.
 */
static int
str2global(void const *str, size_t str_len, struct rpki_uri *uri)
{
	uri->global_len = str_len;
	return string_clone(str, str_len, &uri->global);
}

/**
 * Initializes @uri->global given manifest path @mft and its referenced file
 * @ia5.
 *
 * ie. if @mft is "rsync://a/b/c.mft" and @ia5 is "d/e/f.cer", @uri->global will
 * be "rsync://a/b/d/e/f.cer".
 */
static int
ia5str2global(struct rpki_uri *uri, char const *mft, IA5String_t *ia5)
{
	char *joined;
	char *slash_pos;
	int dir_len;

	/*
	 * IA5String is a subset of ASCII. However, IA5String_t doesn't seem to
	 * be guaranteed to be NULL-terminated.
	 * `(char *) ia5->buf` is fair, but `strlen(ia5->buf)` is not.
	 */

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

/**
 * Initializes @uri->local by converting @uri->global.
 *
 * For example, given local cache repository "/tmp/rpki" and global uri
 * "rsync://rpki.ripe.net/repo/manifest.mft", initializes @uri->local as
 * "/tmp/rpki/rpki.ripe.net/repo/manifest.mft".
 *
 * By contract, if @guri is not RSYNC, this will return ENOTRSYNC.
 * This often should not be treated as an error; please handle gracefully.
 */
static int
g2l(char const *global, size_t global_len, char **result)
{
	static char const *const PREFIX = "rsync://";
	char *local;
	size_t prefix_len;
	size_t extra_slash;
	size_t offset;

	prefix_len = strlen(PREFIX);

	if (global_len < prefix_len
	    || strncmp(PREFIX, global, prefix_len) != 0) {
		pr_err("Global URI '%s' does not begin with '%s'.",
		    global, PREFIX);
		return ENOTRSYNC; /* Not an error, so not negative */
	}

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
	return 0;
}

static int
autocomplete_local(struct rpki_uri *uri)
{
	return g2l(uri->global, uri->global_len, &uri->local);
}

int
uri_init(struct rpki_uri *uri, void const *guri, size_t guri_len)
{
	int error;

	error = str2global(guri, guri_len, uri);
	if (error)
		return error;

	error = autocomplete_local(uri);
	if (error) {
		free(uri->global);
		return error;
	}

	return 0;
}

/**
 * Do not call this function unless you're sure that @guri is NULL-terminated.
 */
int uri_init_str(struct rpki_uri *uri, char const *guri)
{
	return uri_init(uri, guri, strlen(guri));
}

/*
 * Manifests URIs are a little special in that they are relative.
 */
int
uri_init_mft(struct rpki_uri *uri, char const *mft, IA5String_t *ia5)
{
	int error;

	error = ia5str2global(uri, mft, ia5);
	if (error)
		return error;

	error = autocomplete_local(uri);
	if (error)
		free(uri->global);

	return error;
}

int
uri_init_ad(struct rpki_uri *uri, ACCESS_DESCRIPTION *ad)
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
	return uri_init(uri, ASN1_STRING_get0_data(asn1_string),
	    ASN1_STRING_length(asn1_string));
}

void
uri_cleanup(struct rpki_uri *uri)
{
	free(uri->global);
	free(uri->local);
}

/* @ext must include the period. */
bool
uri_has_extension(struct rpki_uri const *uri, char const *ext)
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
uri_is_certificate(struct rpki_uri const *uri)
{
	return uri_has_extension(uri, ".cer");
}

int
uri_g2l(char const *global, char **local)
{
	return g2l(global, strlen(global), local);
}
