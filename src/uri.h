#ifndef SRC_URI_H_
#define SRC_URI_H_

#include <stdbool.h>
#include <libcmscodec/IA5String.h>
#include <openssl/x509v3.h>

/**
 * These are expected to live on the stack, or as part of other objects.
 *
 * All rpki_uris are guaranteed to be RSYNC URLs right now.
 *
 * Design notes:
 *
 * Because we need to generate @local from @global, @global's allowed character
 * set must be a subset of @local. Because this is Unix, @local must never
 * contain NULL (except as a terminating character). Therefore, even though IA5
 * allows NULL, @global won't. TODO (NOW) validate this on constructors.
 *
 * Because we will simply embed @global (minus "rsync://") into @local, @local's
 * encoding must be IA5-compatible. In other words, UTF-16 and UTF-32 are out of
 * the question.
 */
struct rpki_uri {
	/**
	 * "Global URI".
	 * The one that always starts with "rsync://".
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

	/* "local_len" is not needed for now. */
};

int uri_init(struct rpki_uri *, void const *, size_t);
int uri_init_str(struct rpki_uri *, char const *, size_t);
int uri_init_mft(struct rpki_uri *, char const *, IA5String_t *);
int uri_init_ad(struct rpki_uri *, ACCESS_DESCRIPTION *);
int uri_clone(struct rpki_uri const *, struct rpki_uri *);
void uri_cleanup(struct rpki_uri *);

bool uri_has_extension(struct rpki_uri const *, char const *);
bool uri_is_certificate(struct rpki_uri const *);

#endif /* SRC_URI_H_ */
