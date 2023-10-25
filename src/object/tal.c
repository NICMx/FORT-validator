#include "object/tal.h"

#include <errno.h>
#include <openssl/evp.h>
#include <sys/queue.h>

#include "alloc.h"
#include "cert_stack.h"
#include "common.h"
#include "config.h"
#include "line_file.h"
#include "log.h"
#include "state.h"
#include "thread_var.h"
#include "validation_handler.h"
#include "crypto/base64.h"
#include "object/certificate.h"
#include "rtr/db/vrps.h"
#include "cache/local_cache.h"

#define TAL_FILE_EXTENSION	".tal"
typedef int (*foreach_uri_cb)(struct tal *, struct rpki_uri *, void *);

struct uris {
	struct rpki_uri **array; /* This is an array of rpki URIs. */
	unsigned int count;
	unsigned int size;
	unsigned int rsync_count;
	unsigned int https_count;
};

struct tal {
	char const *file_name;
	struct uris uris;
	unsigned char *spki; /* Decoded; not base64. */
	size_t spki_len;
};

struct validation_thread {
	/* TAL file name */
	char *tal_file;
	/*
	 * Try to use the TA from the local cache? Only if none of the URIs
	 * was sync'd.
	 */
	bool retry_local;
	/* Try to sync the current TA URI? */
	bool sync_files;
	void *arg;
	int exit_status;
	/* This should also only be manipulated by the parent thread. */
	SLIST_ENTRY(validation_thread) next;
};

/* List of threads, one per TAL file */
SLIST_HEAD(threads_list, validation_thread);

struct tal_param {
	struct thread_pool *pool;
	struct db_table *db;
	struct threads_list threads;
};

static void
uris_init(struct uris *uris)
{
	uris->count = 0;
	uris->rsync_count = 0;
	uris->https_count = 0;
	uris->size = 4; /* Most TALs only define one. */
	uris->array = pmalloc(uris->size * sizeof(struct rpki_uri *));
}

static void
uris_destroy(struct uris *uris)
{
	unsigned int i;
	for (i = 0; i < uris->count; i++)
		uri_refput(uris->array[i]);
	free(uris->array);
}

static int
uris_add(struct uris *uris, char *uri)
{
	struct rpki_uri *new;
	int error;

	if (str_starts_with(uri, "rsync://"))
		error = uri_create(&new, UT_RSYNC, uri);
	else if (str_starts_with(uri, "https://"))
		error = uri_create(&new, UT_HTTPS, uri);
	else
		error = pr_op_err("TAL has non-RSYNC/HTTPS URI: %s", uri);
	if (error)
		return error;

	if (uri_is_rsync(new))
		uris->rsync_count++;
	else
		uris->https_count++;

	if (uris->count + 1 >= uris->size) {
		uris->size *= 2;
		uris->array = realloc(uris->array,
		    uris->size * sizeof(struct rpki_uri *));
	}

	uris->array[uris->count++] = new;
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
		return pr_op_err("TAL file is empty.");
	if (strcmp(uri, "") == 0) {
		free(uri);
		return pr_op_err("There's no URI in the first line of the TAL.");
	} else if (strncmp(uri, "#", 1) == 0) {
		/* More comments expected, or an URI */
		do {
			free(uri); /* Ignore the comment */
			error = lfile_read(lfile, &uri);
			if (error)
				return error;
			if (uri == NULL)
				return pr_op_err("TAL file ended prematurely. (Expected more comments or an URI list.)");
			if (strcmp(uri, "") == 0) {
				free(uri);
				return pr_op_err("TAL file comments syntax error. (Expected more comments or an URI list.)");
			}
			/* Not a comment, probably the URI(s) */
			if (strncmp(uri, "#", 1) != 0)
				break;
		} while (true);
	}

	do {
		error = uris_add(uris, uri);
		free(uri); /* Won't be needed anymore */
		if (error)
			return error;

		error = lfile_read(lfile, &uri);
		if (error)
			return error;

		if (uri == NULL)
			return pr_op_err("TAL file ended prematurely. (Expected URI list, blank line and public key.)");
		if (strcmp(uri, "") == 0) {
			free(uri);
			return 0; /* Happy path */
		}
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

	for (i = 0; i < len; i++)
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
	result = pmalloc(new_size + 1);
	buf = pmalloc(BUF_SIZE);

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
			pr_op_err("File reading error. Presumably, the error message is '%s.'",
			    strerror(error));
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
	if (offset != new_size)
		result = prealloc(result, offset + 1);
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
	tal->spki = pmalloc(alloc_size);

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
		return op_crypto_err("BIO_new_mem_buf() returned NULL");
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

	lfile = NULL; /* Warning shutupper */
	error = lfile_open(file_name, &lfile);
	if (error) {
		pr_op_err("Error opening file '%s': %s", file_name,
		    strerror(abs(error)));
		return error;
	}

	tal = pmalloc(sizeof(struct tal));

	tal->file_name = file_name;
	uris_init(&tal->uris);
	error = read_uris(lfile, &tal->uris);
	if (error)
		goto fail;
	error = read_spki(lfile, tal);
	if (error)
		goto fail;

	lfile_close(lfile);
	*result = tal;
	return 0;

fail:
	uris_destroy(&tal->uris);
	free(tal);
	lfile_close(lfile);
	return error;
}

void
tal_destroy(struct tal *tal)
{
	if (tal == NULL)
		return;

	uris_destroy(&tal->uris);
	free(tal->spki);
	free(tal);
}

static int
foreach(enum uri_type const *filter, struct tal *tal,
    foreach_uri_cb cb, void *arg)
{
	struct rpki_uri *uri;
	unsigned int i;
	int error;

	for (i = 0; i < tal->uris.count; i++) {
		uri = tal->uris.array[i];
		if (filter == NULL || (*filter) == uri_get_type(uri)) {
			error = cb(tal, uri, arg);
			if (error)
				return error;
		}
	}

	return 0;
}

static int
foreach_uri(struct tal *tal, foreach_uri_cb cb, void *arg)
{
	static const enum uri_type HTTP = UT_HTTPS;
	static const enum uri_type RSYNC = UT_RSYNC;
	int error;

	if (config_get_http_priority() > config_get_rsync_priority()) {
		error = foreach(&HTTP, tal, cb, arg);
		if (!error)
			error = foreach(&RSYNC, tal, cb, arg);

	} else if (config_get_http_priority() < config_get_rsync_priority()) {
		error = foreach(&RSYNC, tal, cb, arg);
		if (!error)
			error = foreach(&HTTP, tal, cb, arg);

	} else {
		error = foreach(NULL, tal, cb, arg);

	}

	return error;
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
	 * key." (RFC 8630)
	 *
	 * A "hard error" is any other error.
	 */

	struct validation_handler validation_handler;
	struct validation_thread *thread;
	struct validation *state;
	struct cert_stack *certstack;
	struct deferred_cert deferred;
	int error;

	thread = arg;

	validation_handler.handle_roa_v4 = handle_roa_v4;
	validation_handler.handle_roa_v6 = handle_roa_v6;
	validation_handler.handle_router_key = handle_router_key;
	validation_handler.arg = thread->arg;

	error = validation_prepare(&state, tal, &validation_handler);
	if (error)
		return ENSURE_NEGATIVE(error);

	if (thread->sync_files) {
		error = cache_download(uri, NULL);
		/* Reminder: there's a positive error: EREQFAILED */
		if (error) {
			validation_destroy(state);
			return pr_val_warn(
			    "TAL URI '%s' could not be downloaded.",
			    uri_val_get_printable(uri));
		}
	} else {
		/* Look for local files */
		if (!valid_file_or_dir(uri_get_local(uri), true, false,
		    pr_val_err)) {
			validation_destroy(state);
			return 0; /* Error already logged */
		}
	}

	/* At least one URI was sync'd */
	thread->retry_local = false;

	pr_val_debug("TAL URI '%s' {", uri_val_get_printable(uri));

	if (!uri_is_certificate(uri)) {
		error = pr_op_err("TAL URI does not point to a certificate. (Expected .cer, got '%s')",
		    uri_op_get_printable(uri));
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
	pr_val_debug("}");
	return error;
}

static void
do_file_validation(void *thread_arg)
{
	struct validation_thread *thread = thread_arg;
	struct tal *tal;
	int error;

	fnstack_init();
	fnstack_push(thread->tal_file);

	error = tal_load(thread->tal_file, &tal);
	if (error)
		goto end;

	error = foreach_uri(tal, handle_tal_uri, thread);
	if (error > 0) {
		error = 0;
		goto destroy_tal;
	} else if (error < 0) {
		goto destroy_tal;
	}

	if (!thread->retry_local) {
		error = pr_op_err("None of the URIs of the TAL '%s' yielded a successful traversal.",
		    thread->tal_file);
		goto destroy_tal;
	}

	thread->sync_files = false;
	pr_val_warn("Looking for the TA certificate at the local files.");

	error = foreach_uri(tal, handle_tal_uri, thread);
	if (error > 0)
		error = 0;
	else if (error == 0)
		error = pr_op_err("None of the URIs of the TAL '%s' yielded a successful traversal.",
		    thread->tal_file);

destroy_tal:
	tal_destroy(tal);
end:
	fnstack_cleanup();
	thread->exit_status = error;
}

static void
thread_destroy(struct validation_thread *thread)
{
	free(thread->tal_file);
	free(thread);
}

/* Creates a thread for the @tal_file */
static int
__do_file_validation(char const *tal_file, void *arg)
{
	struct tal_param *t_param = arg;
	struct validation_thread *thread;

	thread = pmalloc(sizeof(struct validation_thread));

	thread->tal_file = pstrdup(tal_file);
	thread->arg = t_param->db;
	thread->exit_status = -EINTR;
	thread->retry_local = true;
	thread->sync_files = true;

	thread_pool_push(t_param->pool, thread->tal_file, do_file_validation,
	    thread);
	SLIST_INSERT_HEAD(&t_param->threads, thread, next);

	return 0;
}

int
perform_standalone_validation(struct thread_pool *pool, struct db_table *table)
{
	struct tal_param param;
	struct validation_thread *thread;
	int error;

	param.pool = pool;
	param.db = table;
	SLIST_INIT(&param.threads);

	error = process_file_or_dir(config_get_tal(), TAL_FILE_EXTENSION, true,
	    __do_file_validation, &param);
	if (error) {
		/* End all thread data */
		while (!SLIST_EMPTY(&param.threads)) {
			thread = SLIST_FIRST(&param.threads);
			SLIST_REMOVE_HEAD(&param.threads, next);
			thread_destroy(thread);
		}
		return error;
	}

	/* Wait for all */
	thread_pool_wait(pool);

	while (!SLIST_EMPTY(&param.threads)) {
		thread = SLIST_FIRST(&param.threads);
		SLIST_REMOVE_HEAD(&param.threads, next);
		if (thread->exit_status) {
			error = thread->exit_status;
			pr_op_warn("Validation from TAL '%s' yielded error, discarding any other validation results.",
			    thread->tal_file);
		}
		thread_destroy(thread);
	}

	/* If one thread has errors, we can't keep the resulting table. */
	return error;
}
