#include "tal.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <openssl/evp.h>

#include "line_file.h"
#include "log.h"
#include "crypto/base64.h"

struct uri {
	char *string;
	SLIST_ENTRY(uri) next;
};

SLIST_HEAD(uri_list, uri);

struct tal {
	struct uri_list uris;
	unsigned char *spki; /* Decoded; not base64. */
	size_t spki_len;
};

static void
uri_destroy(struct uri *uri)
{
	free(uri->string);
	free(uri);
}

static void
uris_destroy(struct uri_list *uris)
{
	struct uri *uri;

	while (!SLIST_EMPTY(uris)) {
		uri = SLIST_FIRST(uris);
		SLIST_REMOVE_HEAD(uris, next);
		uri_destroy(uri);
	}
}

static int
read_uri(struct line_file *lfile, struct uri **result)
{
	struct uri *uri;
	int err;

	uri = malloc(sizeof(struct uri));
	if (uri == NULL)
		return pr_enomem();

	err = lfile_read(lfile, &uri->string);
	if (err) {
		free(uri);
		return err;
	}

	*result = uri;
	return 0;
}

static int
read_uris(struct line_file *lfile, struct uri_list *uris)
{
	struct uri *previous, *uri;
	int err;

	err = read_uri(lfile, &uri);
	if (err)
		return err;

	if (strcmp(uri->string, "") == 0) {
		uri_destroy(uri);
		return pr_err("TAL file %s contains no URIs",
		    lfile_name(lfile));
	}

	SLIST_INIT(uris);
	SLIST_INSERT_HEAD(uris, uri, next);

	do {
		previous = uri;

		err = read_uri(lfile, &uri);
		if (err)
			return err;

		if (strcmp(uri->string, "") == 0) {
			uri_destroy(uri);
			return 0; /* Happy path */
		}

		SLIST_INSERT_AFTER(previous, uri, next);
	} while (true);
}

/*
 * Will usually allocate slightly more because of the newlines, but I'm fine
 * with it.
 */
static size_t
get_spki_alloc_size(struct line_file *lfile)
{
	struct stat st;
	size_t result;

	stat(lfile_name(lfile), &st);
	result = st.st_size - lfile_offset(lfile);

	return EVP_DECODE_LENGTH(result);
}

static int
read_spki(struct line_file *lfile, struct tal *tal)
{
	BIO *encoded; /* base64 encoded. */
	size_t alloc_size;
	int error;

	alloc_size = get_spki_alloc_size(lfile);
	tal->spki = malloc(alloc_size);
	if (tal->spki == NULL)
		return -ENOMEM;

	encoded = BIO_new_fp(lfile_fd(lfile), BIO_NOCLOSE);
	if (encoded == NULL) {
		free(tal->spki);
		return crypto_err("BIO_new_fp() returned NULL");
	}

	error = base64_decode(encoded, tal->spki, alloc_size, &tal->spki_len);
	if (error)
		free(tal->spki);

	BIO_free(encoded);
	return error;
}

int
tal_load(const char *file_name, struct tal **result)
{
	struct line_file *lfile;
	struct tal *tal;
	int err;

	err = lfile_open(file_name, &lfile);
	if (err)
		return err;

	tal = malloc(sizeof(struct tal));
	if (tal == NULL) {
		lfile_close(lfile);
		return -ENOMEM;
	}

	err = read_uris(lfile, &tal->uris);
	if (err) {
		free(tal);
		lfile_close(lfile);
		return err;
	}

	err = read_spki(lfile, tal);
	if (err) {
		uris_destroy(&tal->uris);
		free(tal);
		lfile_close(lfile);
		return err;
	}

	lfile_close(lfile);
	*result = tal;
	return 0;
}

void tal_destroy(struct tal *tal)
{
	if (tal == NULL)
		return;

	uris_destroy(&tal->uris);
	free(tal->spki);
	free(tal);
}

int
foreach_uri(struct tal *tal, foreach_uri_cb cb)
{
	struct uri *cursor;
	int error;

	SLIST_FOREACH(cursor, &tal->uris, next) {
		error = cb(tal, cursor->string);
		if (error)
			return error;
	}

	return 0;
}

void
tal_get_spki(struct tal *tal, unsigned char const **buffer, size_t *len)
{
	*buffer = tal->spki;
	*len = tal->spki_len;
}
