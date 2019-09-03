#define _GNU_SOURCE

#include "tal.h"

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <openssl/evp.h>

#include "cert_stack.h"
#include "common.h"
#include "config.h"
#include "line_file.h"
#include "log.h"
#include "random.h"
#include "state.h"
#include "thread_var.h"
#include "validation_handler.h"
#include "crypto/base64.h"
#include "object/certificate.h"
#include "rsync/rsync.h"
#include "rtr/db/vrps.h"

#define TAL_FILE_EXTENSION	".tal"

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

struct fv_param {
	char *tal_file;
	void *arg;
};

struct thread {
	pthread_t pid;
	char *file;
	SLIST_ENTRY(thread) next;
};

/* List of threads, one per TAL file */
SLIST_HEAD(threads_list, thread) threads;

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

static size_t
get_spki_orig_size(struct line_file *lfile)
{
	struct stat st;
	size_t result;

	stat(lfile_name(lfile), &st);
	result = st.st_size - lfile_offset(lfile);
	return result;
}

/*
 * Will usually allocate slightly more because of the newlines, but I'm fine
 * with it.
 */
static size_t
get_spki_alloc_size(struct line_file *lfile)
{
	return EVP_DECODE_LENGTH(get_spki_orig_size(lfile));
}

static char *
locate_char(char *str, size_t len, char find)
{
	size_t i;

	for(i = 0; i < len; i++)
		if (str[i] == find)
			return str + i;
	return NULL;
}

/*
 * Get the base64 chars from @lfile and allocate to @out with lines no greater
 * than 65 chars (including line feed).
 *
 * Why? LibreSSL doesn't like lines greater than 80 chars, so use a common
 * length per line.
 */
static int
base64_sanitize(struct line_file *lfile, char **out)
{
#define BUF_SIZE 65
	FILE *fd;
	char *buf, *result, *eol;
	size_t original_size, new_size;
	size_t fread_result, offset;
	int error;

	/*
	 * lfile_read() isn't called since the lines aren't returned as needed
	 * "sanitized" (a.k.a. each line with a desired length)
	 */
	original_size = get_spki_orig_size(lfile);
	new_size = original_size + (original_size / BUF_SIZE);
	result = malloc(new_size + 1);
	if (result == NULL)
		return pr_enomem();

	buf = malloc(BUF_SIZE);
	if (buf == NULL) {
		free(result);
		return pr_enomem();
	}

	fd = lfile_fd(lfile);
	offset = 0;
	while ((fread_result = fread(buf, 1,
	    (original_size > BUF_SIZE) ? BUF_SIZE : original_size, fd)) > 0) {
		error = ferror(lfile_fd(lfile));
		if (error) {
			/*
			 * The manpage doesn't say that the result is an error
			 * code. It literally doesn't say how to get an error
			 * code.
			 */
			pr_errno(error,
			    "File reading error. Error message (apparently)");
			goto free_result;
		}

		original_size -= fread_result;
		eol = locate_char(buf, fread_result, '\n');
		/* Larger than buffer length, add LF and copy last char */
		if (eol == NULL) {
			memcpy(&result[offset], buf, fread_result - 1);
			offset += fread_result - 1;
			result[offset] = '\n';
			result[offset + 1] = buf[fread_result - 1];
			offset += 2;
			continue;
		}
		/* Copy till last LF */
		memcpy(&result[offset], buf, eol - buf + 1);
		offset += eol - buf + 1;
		if (eol - buf + 1 < fread_result) {
			/* And add new line with remaining chars */
			memcpy(&result[offset], eol + 1,
			    buf + fread_result - 1 - eol);
			offset += buf + fread_result -1 - eol;
			result[offset] = '\n';
			offset++;
		}
	}
	/* Reallocate to exact size and add nul char */
	if (offset != new_size + 1) {
		eol = realloc(result, offset + 1);
		if (eol == NULL) {
			error = pr_enomem();
			goto free_result;
		}
		result = eol;
	}
	free(buf);
	result[offset] = '\0';

	*out = result;
	return 0;
free_result:
	free(buf);
	free(result);
	return error;
#undef BUF_SIZE
}

static int
read_spki(struct line_file *lfile, struct tal *tal)
{
	BIO *encoded; /* base64 encoded. */
	char *tmp;
	size_t alloc_size;
	int error;

	alloc_size = get_spki_alloc_size(lfile);
	tal->spki = malloc(alloc_size);
	if (tal->spki == NULL)
		return pr_enomem();

	tmp = NULL;
	error = base64_sanitize(lfile, &tmp);
	if (error) {
		free(tal->spki);
		return error;
	}

	encoded = BIO_new_mem_buf(tmp, -1);
	if (encoded == NULL) {
		free(tal->spki);
		free(tmp);
		return crypto_err("BIO_new_mem_buf() returned NULL");
	}

	error = base64_decode(encoded, tal->spki, true, alloc_size,
		    &tal->spki_len);
	if (error)
		free(tal->spki);

	free(tmp);
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
foreach_uri(struct tal *tal, foreach_uri_cb cb, void *arg)
{
	struct rpki_uri *uri;
	unsigned int i;
	int error;

	for (i = 0; i < tal->uris.count; i++) {
		error = uri_create_str(&uri, tal->uris.array[i],
		    strlen(tal->uris.array[i]));
		if (error == ENOTRSYNC) {
			/* Log level should probably be INFO. */
			pr_debug("TAL has non-RSYNC URI; ignoring.");
			continue;
		}
		if (error)
			return error;

		error = cb(tal, uri, arg);
		uri_refput(uri);
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
handle_tal_uri(struct tal *tal, struct rpki_uri *uri, void *arg)
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

	struct validation_handler validation_handler;
	struct validation *state;
	struct cert_stack *certstack;
	struct deferred_cert deferred;
	int error;

	validation_handler.handle_roa_v4 = handle_roa_v4;
	validation_handler.handle_roa_v6 = handle_roa_v6;
	validation_handler.handle_router_key = handle_router_key;
	validation_handler.arg = arg;

	error = validation_prepare(&state, tal, &validation_handler);
	if (error)
		return ENSURE_NEGATIVE(error);

	error = download_files(uri, true, false);
	if (error) {
		pr_warn("TAL '%s' could not be RSYNC'd.",
		    uri_get_printable(uri));
		validation_destroy(state);
		return ENSURE_NEGATIVE(error);
	}

	pr_debug_add("TAL URI '%s' {", uri_get_printable(uri));

	if (!uri_is_certificate(uri)) {
		error = pr_err("TAL file does not point to a certificate. (Expected .cer, got '%s')",
		    uri_get_printable(uri));
		goto fail;
	}

	/* Handle root certificate. */
	error = certificate_traverse(NULL, uri);
	if (error) {
		switch (validation_pubkey_state(state)) {
		case PKS_INVALID:
			error = 0; /* Try a different TAL URI. */
			goto end;
		case PKS_VALID:
		case PKS_UNTESTED:
			goto fail; /* Reject the TAL. */
		}

		pr_crit("Unknown public key state: %u",
		    validation_pubkey_state(state));
	}

	/*
	 * From now on, the tree should be considered valid, even if subsequent
	 * certificates fail.
	 * (the root validated successfully; subtrees are isolated problems.)
	 */

	/* Handle every other certificate. */
	certstack = validation_certstack(state);
	if (certstack == NULL)
		pr_crit("Validation state has no certificate stack");

	do {
		error = deferstack_pop(certstack, &deferred);
		if (error == -ENOENT) {
			/* No more certificates left; we're done. */
			error = 1;
			goto end;
		} else if (error) /* All other errors are critical, currently */
			pr_crit("deferstack_pop() returned illegal %d.", error);

		/*
		 * Ignore result code; remaining certificates are unrelated,
		 * so they should not be affected.
		 */
		certificate_traverse(deferred.pp, deferred.uri);

		uri_refput(deferred.uri);
		rpp_refput(deferred.pp);
	} while (true);

fail:	error = ENSURE_NEGATIVE(error);
end:	validation_destroy(state);
	pr_debug_rm("}");
	return error;
}

static void *
do_file_validation(void *thread_arg)
{
	struct fv_param param;
	struct tal *tal;
	int error;

	memcpy(&param, thread_arg, sizeof(param));
	free(thread_arg);

	fnstack_init();
	fnstack_push(param.tal_file);

	error = tal_load(param.tal_file, &tal);
	if (error)
		goto end;

	if (config_get_shuffle_tal_uris())
		tal_shuffle_uris(tal);
	error = foreach_uri(tal, handle_tal_uri, param.arg);
	if (error > 0)
		error = 0;
	else if (error == 0)
		error = pr_err("None of the URIs of the TAL '%s' yielded a successful traversal.",
		    param.tal_file);

	tal_destroy(tal);
end:
	fnstack_cleanup();
	free(param.tal_file);
	return NULL;
}

static void
thread_destroy(struct thread *thread)
{
	free(thread->file);
	free(thread);
}

/* Creates a thread for the @tal_file */
static int
__do_file_validation(char const *tal_file, void *arg)
{
	struct thread *thread;
	struct fv_param *param;
	static pthread_t pid;
	int error;

	param = malloc(sizeof(struct fv_param));
	if (param == NULL)
		return pr_enomem();

	param->tal_file = strdup(tal_file);
	param->arg = arg;

	errno = pthread_create(&pid, NULL, do_file_validation, param);
	if (errno) {
		error = -pr_errno(errno,
		    "Could not spawn the file validation thread");
		goto free_param;
	}

	thread = malloc(sizeof(struct thread));
	if (thread == NULL) {
		close_thread(pid, tal_file);
		error = -EINVAL;
		goto free_param;
	}

	thread->pid = pid;
	thread->file = strdup(tal_file);
	SLIST_INSERT_HEAD(&threads, thread, next);

	return 0;
free_param:
	free(param->tal_file);
	free(param);
	return error;
}

int
perform_standalone_validation(struct db_table *table)
{
	struct thread *thread;
	int error;

	SLIST_INIT(&threads);
	error = process_file_or_dir(config_get_tal(), TAL_FILE_EXTENSION,
	    __do_file_validation, table);
	if (error)
		return error;

	/* Wait for all */
	while (!SLIST_EMPTY(&threads)) {
		thread = threads.slh_first;
		error = pthread_join(thread->pid, NULL);
		if (error)
			pr_crit("pthread_join() threw %d on the '%s' thread.",
			    error, thread->file);
		SLIST_REMOVE_HEAD(&threads, next);
		thread_destroy(thread);
	}

	return error;
}

void
terminate_standalone_validation(void)
{
	struct thread *thread;

	/* End all threads */
	while (!SLIST_EMPTY(&threads)) {
		thread = threads.slh_first;
		close_thread(thread->pid, thread->file);
		SLIST_REMOVE_HEAD(&threads, next);
		thread_destroy(thread);
	}
}
