#define _GNU_SOURCE

#include "tal.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/evp.h>

#include "line_file.h"
#include "log.h"
#include "random.h"
#include "crypto/base64.h"

struct uris {
	char **array; /* This is an array of string pointers. */
	unsigned int count;
	unsigned int size;
};

struct tal {
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

	if (strcmp(uri, "") == 0) {
		free(uri);
		return pr_err("TAL file contains no URIs");
	}

	error = uris_add(uris, uri);
	if (error)
		return error;

	do {
		error = lfile_read(lfile, &uri);
		if (error)
			return error;

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

int
tal_load(const char *file_name, struct tal **result)
{
	struct line_file *lfile;
	struct tal *tal;
	int error;

	error = lfile_open(file_name, &lfile);
	if (error)
		goto fail4;

	tal = malloc(sizeof(struct tal));
	if (tal == NULL) {
		error = -ENOMEM;
		goto fail3;
	}

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
		error = uri_init_str(&uri, tal->uris.array[i]);
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

void
tal_get_spki(struct tal *tal, unsigned char const **buffer, size_t *len)
{
	*buffer = tal->spki;
	*len = tal->spki_len;
}
