#ifndef SRC_URI_H_
#define SRC_URI_H_

#include <stdbool.h>
#include <libcmscodec/IA5String.h>
#include <openssl/x509v3.h>

/**
 * These are expected to live on the stack, or as part of other objects.
 */
struct rpki_uri {
	/**
	 * "Global URI".
	 * The one that always starts with "rsync://".
	 * As currently implemented, it's expected to live in the heap.
	 */
	char *global;
	/** Length of @global. */
	size_t global_len;

	/**
	 * "Local URI".
	 * The file pointed by @global, but cached in the local filesystem.
	 * As currently implemented, it's expected to live in the heap.
	 */
	char *local;

	/* "local_len" is not needed for now. */
};

int uri_init(struct rpki_uri *, void const *, size_t);
int uri_init_str(struct rpki_uri *uri, char const *guri);
int uri_init_mft(struct rpki_uri *, char const *, IA5String_t *);
int uri_init_ad(struct rpki_uri *, ACCESS_DESCRIPTION *ad);
void uri_cleanup(struct rpki_uri *);

bool uri_has_extension(struct rpki_uri const *, char const *);
bool uri_is_certificate(struct rpki_uri const *);

int uri_g2l(char const *, char **);

#endif /* SRC_URI_H_ */
