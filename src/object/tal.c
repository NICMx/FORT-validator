#define _GNU_SOURCE

#include "tal.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/evp.h>

#include "common.h"
#include "config.h"
#include "line_file.h"
#include "log.h"
#include "random.h"
#include "state.h"
#include "thread_var.h"
#include "crypto/base64.h"
#include "object/certificate.h"
#include "rsync/rsync.h"

struct uris {
	char **array; /* This is an array of string pointers. */
	unsigned int count;
	unsigned int size;
};

struct tal {
	char const *file_name;
	struct uris uris;
	unsigned char *spki; /* Decoded; not base64. */
	size_t spki_len;
};

static int
uris_init(struct uris *uris)
{
	uris->count = 0;
	uris->size = 4; /* Most TALs only define one. */
	uris->array = malloc(uris->size * sizeof(char *));
	return (uris->array != NULL) ? 0 : -ENOMEM;
}

static void
uris_destroy(struct uris *uris)
{
	unsigned int i;
	for (i = 0; i < uris->count; i++)
		free(uris->array[i]);
	free(uris->array);
}

static int
uris_add(struct uris *uris, char *uri)
{
	char **tmp;

	if (uris->count + 1 >= uris->size) {
		uris->size *= 2;
		tmp = realloc(uris->array, uris->size * sizeof(char *));
		if (tmp == NULL)
			return pr_enomem();
		uris->array = tmp;
	}

	uris->array[uris->count++] = uri;
	return 0;
}

static int
read_uris(struct line_file *lfile, struct uris *uris)
{
	char *uri;
	int error;

	error = lfile_read(lfile, &uri);
	if (error)
		return error;

	if (uri == NULL)
		return pr_err("TAL file is empty.");
	if (strcmp(uri, "") == 0) {
		free(uri);
		return pr_err("There's no URI in the first line of the TAL.");
	}

	error = uris_add(uris, uri);
	if (error)
		return error;

	do {
		error = lfile_read(lfile, &uri);
		if (error)
			return error;

		if (uri == NULL)
			return pr_err("TAL file ended prematurely. (Expected URI list, blank line and public key.)");
		if (strcmp(uri, "") == 0) {
			free(uri);
			return 0; /* Happy path */
		}

		error = uris_add(uris, uri);
		if (error)
			return error;
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

/**
 * @file_name is expected to outlive @result.
 */
int
tal_load(char const *file_name, struct tal **result)
{
	struct line_file *lfile;
	struct tal *tal;
	int error;

	error = lfile_open(file_name, &lfile);
	if (error) {
		pr_errno(error, "Error opening file '%s'", file_name);
		goto fail4;
	}

	tal = malloc(sizeof(struct tal));
	if (tal == NULL) {
		error = -ENOMEM;
		goto fail3;
	}

	tal->file_name = file_name;

	error = uris_init(&tal->uris);
	if (error)
		goto fail2;

	error = read_uris(lfile, &tal->uris);
	if (error)
		goto fail1;

	error = read_spki(lfile, tal);
	if (error)
		goto fail1;

	lfile_close(lfile);
	*result = tal;
	return 0;

fail1:
	uris_destroy(&tal->uris);
fail2:
	free(tal);
fail3:
	lfile_close(lfile);
fail4:
	return error;
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
	struct rpki_uri uri;
	unsigned int i;
	int error;

	for (i = 0; i < tal->uris.count; i++) {
		error = uri_init_str(&uri, tal->uris.array[i],
		    strlen(tal->uris.array[i]));
		if (error == ENOTRSYNC) {
			/* Log level should probably be INFO. */
			pr_debug("TAL has non-RSYNC URI; ignoring.");
			continue;
		}
		if (error)
			return error;

		error = cb(tal, &uri);
		uri_cleanup(&uri);
		if (error)
			return error;
	}

	return 0;
}

void
tal_shuffle_uris(struct tal *tal)
{
	char **array = tal->uris.array;
	unsigned int count = tal->uris.count;
	char *tmp;
	long random_index;
	unsigned int i;

	random_init();

	for (i = 0; i < count; i++) {
		tmp = array[i];
		random_index = random_at_most(count - 1 - i) + i;
		array[i] = array[random_index];
		array[random_index] = tmp;
	}
}

char const *
tal_get_file_name(struct tal *tal)
{
	return tal->file_name;
}

void
tal_get_spki(struct tal *tal, unsigned char const **buffer, size_t *len)
{
	*buffer = tal->spki;
	*len = tal->spki_len;
}

/**
 * Performs the whole validation walkthrough on uri @uri, which is assumed to
 * have been extracted from a TAL.
 */
static int
handle_tal_uri(struct tal *tal, struct rpki_uri const *uri)
{
	/*
	 * Because of the way the foreach iterates, this function must return
	 *
	 * - 0 on soft errors.
	 * - `> 0` on URI handled successfully.
	 * - `< 0` on hard errors.
	 *
	 * A "soft error" is "the connection to the preferred URI fails, or the
	 * retrieved CA certificate public key does not match the TAL public
	 * key." (RFC 7730)
	 *
	 * A "hard error" is any other error.
	 */

	struct validation *state;
	int error;

	error = download_files(uri, true);
	if (error) {
		return pr_warn("TAL URI '%s' could not be RSYNC'd.",
		    uri->global);
	}

	error = validation_prepare(&state, tal);
	if (error)
		return ENSURE_NEGATIVE(error);

	pr_debug_add("TAL URI '%s' {", uri_get_printable(uri));

	if (!uri_is_certificate(uri)) {
		pr_err("TAL file does not point to a certificate. (Expected .cer, got '%s')",
		    uri_get_printable(uri));
		error = -EINVAL;
		goto end;
	}

	error = certificate_traverse(NULL, uri, NULL, true);
	if (error) {
		switch (validation_pubkey_state(state)) {
		case PKS_INVALID:
			error = 0;
			break;
		case PKS_VALID:
		case PKS_UNTESTED:
			error = ENSURE_NEGATIVE(error);
			break;
		}
	} else {
		error = 1;
	}

end:	validation_destroy(state);
	pr_debug_rm("}");
	return error;
}

/* TODO set @updated */
int
perform_standalone_validation(bool *updated)
{
	struct tal *tal;
	int error;

	fnstack_init();
	fnstack_push(config_get_tal());

	error = tal_load(config_get_tal(), &tal);
	if (error)
		goto end;

	if (config_get_shuffle_tal_uris())
		tal_shuffle_uris(tal);
	error = foreach_uri(tal, handle_tal_uri);
	if (error > 0)
		error = 0;
	else if (error == 0)
		error = pr_err("None of the URIs of the TAL yielded a successful traversal.");

end:	tal_destroy(tal);
	fnstack_pop();
	fnstack_cleanup();
	return error;
}
