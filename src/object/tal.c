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
#include "http/http.h"
#include "object/certificate.h"
#include "rsync/rsync.h"
#include "rtr/db/vrps.h"
#include "rrdp/db/db_rrdp.h"

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
	int *exit_status; /* Return status of the file validation */
	char *tal_file;
	void *arg;
};

struct thread {
	pthread_t pid;
	char *file;
	int *exit_status;
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
	} else if (strncmp(uri, "#", 1) == 0) {
		/* More comments expected, or an URI */
		do {
			free(uri); /* Ignore the comment */
			error = lfile_read(lfile, &uri);
			if (error)
				return error;
			if (uri == NULL)
				return pr_err("TAL file ended prematurely. (Expected more comments or an URI list.)");
			if (strcmp(uri, "") == 0) {
				free(uri);
				return pr_err("TAL file comments syntax error. (Expected more comments or an URI list.)");
			}
			/* Not a comment, probably the URI(s) */
			if (strncmp(uri, "#", 1) != 0)
				break;
		} while (true);
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
		error = uri_create_mixed_str(&uri, tal->uris.array[i],
		    strlen(tal->uris.array[i]));
		if (error == ENOTSUPPORTED) {
			pr_info("TAL has non-RSYNC/HTTPS URI; ignoring.");
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

static size_t
write_http_cer(unsigned char *content, size_t size, size_t nmemb, void *arg)
{
	FILE *fd = arg;
	size_t read = size * nmemb;
	size_t written;

	written = fwrite(content, size, nmemb, fd);
	if (written != nmemb)
		return -EINVAL;

	return read;
}

static int
handle_https_uri(struct rpki_uri *uri)
{
	return http_download_file(uri, write_http_cer);
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
	 * key." (RFC 8630)
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

	if (uri_is_rsync(uri))
		error = download_files(uri, true, false);
	else
		error = handle_https_uri(uri);

	if (error) {
		validation_destroy(state);
		return pr_warn("TAL '%s' could not be downloaded.",
		    uri_get_printable(uri));;
	}

	pr_debug("TAL URI '%s' {", uri_get_printable(uri));

	if (!uri_is_certificate(uri)) {
		error = pr_err("TAL file does not point to a certificate. (Expected .cer, got '%s')",
		    uri_get_printable(uri));
		goto fail;
	}

	/*
	 * Set all RRDPs URIs to non-requested, this way we will force the
	 * request on every cycle (to check if there are updates).
	 */
	error = db_rrdp_uris_set_all_unvisited();
	if (error)
		goto end;

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
	pr_debug("}");
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
	/* param.exit_error isn't released since it's from parent thread */
	*param.exit_status = error;
	return NULL;
}

static void
thread_destroy(struct thread *thread)
{
	free(thread->file);
	free(thread->exit_status);
	free(thread);
}

/* Creates a thread for the @tal_file */
static int
__do_file_validation(char const *tal_file, void *arg)
{
	struct thread *thread;
	struct fv_param *param;
	static pthread_t pid;
	int *exit_status;
	int error;

	error = db_rrdp_add_tal(tal_file);
	if (error)
		return error;

	exit_status = malloc(sizeof(int));
	if (exit_status == NULL) {
		error = pr_enomem();
		goto free_db_rrdp;
	}

	param = malloc(sizeof(struct fv_param));
	if (param == NULL) {
		error = pr_enomem();
		goto free_status;
	}

	param->exit_status = exit_status;
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
		error = pr_enomem();
		goto free_param;
	}

	thread->pid = pid;
	thread->file = strdup(tal_file);
	thread->exit_status = exit_status;
	SLIST_INSERT_HEAD(&threads, thread, next);

	return 0;
free_param:
	free(param->tal_file);
	free(param);
free_status:
	free(exit_status);
free_db_rrdp:
	db_rrdp_rem_tal(tal_file);
	return error;
}

int
perform_standalone_validation(struct db_table *table)
{
	struct thread *thread;
	int error, t_error;

	/* Set existent tal RRDP info to non visited */
	db_rrdp_reset_visited_tals();

	SLIST_INIT(&threads);
	error = process_file_or_dir(config_get_tal(), TAL_FILE_EXTENSION,
	    __do_file_validation, table);
	if (error)
		return error;

	/* Wait for all */
	t_error = 0;
	while (!SLIST_EMPTY(&threads)) {
		thread = threads.slh_first;
		error = pthread_join(thread->pid, NULL);
		if (error)
			pr_crit("pthread_join() threw %d on the '%s' thread.",
			    error, thread->file);
		SLIST_REMOVE_HEAD(&threads, next);
		if (*thread->exit_status) {
			t_error = *thread->exit_status;
			pr_warn("Validation from TAL '%s' yielded error, discarding any other validation results.",
			    thread->file);
		}
		thread_destroy(thread);
	}

	/* One thread has errors, validation can't keep the resulting table */
	if (t_error)
		return t_error;

	/* Remove non-visited rrdps URIS by tal */
	db_rrdp_rem_nonvisited_tals();

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
