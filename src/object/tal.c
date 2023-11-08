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

typedef int (*foreach_uri_cb)(struct tal *, struct rpki_uri *, void *);

struct tal {
	char const *file_name;
	struct uri_list uris;
	unsigned char *spki; /* Decoded; not base64. */
	size_t spki_len;
};

struct validation_thread {
	pthread_t pid;
	/* TAL file name */
	char *tal_file;
	struct db_table *db;
	int exit_status;
	/* This should also only be manipulated by the parent thread. */
	SLIST_ENTRY(validation_thread) next;
};

/* List of threads, one per TAL file */
SLIST_HEAD(threads_list, validation_thread);

struct tal_thread_args {
	struct db_table *db;
	struct threads_list threads;
};

struct handle_tal_args {
	struct tal *tal;
	struct db_table *db;
};

static int
add_uri(struct uri_list *uris, char *uri)
{
	struct rpki_uri *new;
	int error;

	if (str_starts_with(uri, "rsync://"))
		error = uri_create(&new, UT_RSYNC, NULL, uri);
	else if (str_starts_with(uri, "https://"))
		error = uri_create(&new, UT_HTTPS, NULL, uri);
	else
		error = pr_op_err("TAL has non-RSYNC/HTTPS URI: %s", uri);
	if (error)
		return error;

	uris_add(uris, new);
	return 0;
}

static int
read_uris(struct line_file *lfile, struct uri_list *uris)
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
		error = add_uri(uris, uri);
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
	uris_cleanup(&tal->uris);
	free(tal);
	lfile_close(lfile);
	return error;
}

void
tal_destroy(struct tal *tal)
{
	if (tal == NULL)
		return;

	uris_cleanup(&tal->uris);
	free(tal->spki);
	free(tal);
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
 * have been extracted from TAL @tal.
 */
static int
handle_tal_uri(struct tal *tal, struct rpki_uri *uri, struct db_table *db)
{
	struct validation_handler validation_handler;
	struct validation *state;
	struct cert_stack *certstack;
	struct deferred_cert deferred;
	int error;

	pr_val_debug("TAL URI '%s' {", uri_val_get_printable(uri));

	validation_handler.handle_roa_v4 = handle_roa_v4;
	validation_handler.handle_roa_v6 = handle_roa_v6;
	validation_handler.handle_router_key = handle_router_key;
	validation_handler.arg = db;

	error = validation_prepare(&state, tal, &validation_handler);
	if (error)
		return ENSURE_NEGATIVE(error);

	if (!uri_is_certificate(uri)) {
		pr_op_err("TAL URI does not point to a certificate. (Expected .cer, got '%s')",
		    uri_op_get_printable(uri));
		error = EINVAL;
		goto end;
	}

	/* Handle root certificate. */
	error = certificate_traverse(NULL, uri);
	if (error) {
		switch (validation_pubkey_state(state)) {
		case PKS_INVALID:
			error = EINVAL;
			goto end;
		case PKS_VALID:
		case PKS_UNTESTED:
			error = ENSURE_NEGATIVE(error);
			goto end;
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
			error = 0; /* No more certificates left; we're done */
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

end:	validation_destroy(state);
	pr_val_debug("}");
	return error;
}

static int
__handle_tal_uri(struct rpki_uri *uri, void *arg)
{
	struct handle_tal_args *args = arg;
	return handle_tal_uri(args->tal, uri, args->db);
}

static void *
do_file_validation(void *arg)
{
	struct validation_thread *thread = arg;
	struct tal *tal;
	struct handle_tal_args handle_args;
	int error;

	fnstack_init();
	fnstack_push(thread->tal_file);

	error = tal_load(thread->tal_file, &tal);
	if (error)
		goto end;

	handle_args.tal = tal;
	handle_args.db = thread->db;
	error = uris_download(&tal->uris, false, __handle_tal_uri, &handle_args);
	if (error)
		pr_op_err("None of the URIs of the TAL '%s' yielded a successful traversal.",
		    thread->tal_file);

	tal_destroy(tal);
end:	fnstack_cleanup();
	thread->exit_status = error;
	return NULL;
}

static void
thread_destroy(struct validation_thread *thread)
{
	free(thread->tal_file);
	free(thread);
}

/* Creates a thread for the @tal_file */
static int
spawn_tal_thread(char const *tal_file, void *arg)
{
	struct tal_thread_args *thread_args = arg;
	struct validation_thread *thread;
	int error;

	thread = pmalloc(sizeof(struct validation_thread));

	thread->tal_file = pstrdup(tal_file);
	thread->db = thread_args->db;
	thread->exit_status = -EINTR;
	SLIST_INSERT_HEAD(&thread_args->threads, thread, next);

	error = pthread_create(&thread->pid, NULL, do_file_validation, thread);
	if (error) {
		pr_op_err("Could not spawn validation thread for %s: %s",
		    tal_file, strerror(error));
		free(thread->tal_file);
		free(thread);
	}

	return error;
}

int
perform_standalone_validation(struct db_table *table)
{
	struct tal_thread_args args;
	struct validation_thread *thread;
	int error, tmperr;

	args.db = table;
	SLIST_INIT(&args.threads);

	/* TODO (fine) Maybe don't spawn threads if there's only one TAL */
	error = foreach_file(config_get_tal(), ".tal", true, spawn_tal_thread,
	    &args);
	if (error) {
		while (!SLIST_EMPTY(&args.threads)) {
			thread = SLIST_FIRST(&args.threads);
			SLIST_REMOVE_HEAD(&args.threads, next);
			thread_destroy(thread);
		}
		return error;
	}

	/* Wait for all */
	while (!SLIST_EMPTY(&args.threads)) {
		thread = SLIST_FIRST(&args.threads);
		tmperr = pthread_join(thread->pid, NULL);
		if (tmperr)
			pr_crit("pthread_join() threw %d (%s) on the '%s' thread.",
			    tmperr, strerror(tmperr), thread->tal_file);
		SLIST_REMOVE_HEAD(&args.threads, next);
		if (thread->exit_status) {
			error = thread->exit_status;
			pr_op_warn("Validation from TAL '%s' yielded error %d (%s); discarding all validation results.",
			    thread->tal_file, error, strerror(abs(error)));
		}
		thread_destroy(thread);
	}

	/* If one thread has errors, we can't keep the resulting table. */
	return error;
}
