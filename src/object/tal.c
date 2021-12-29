#define _GNU_SOURCE

#include "object/tal.h"

#include <errno.h>
#include <unistd.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "common.h"
#include "line_file.h"
#include "state.h"
#include "thread_var.h"
#include "types/uri.h"
#include "types/uri_list.h"
#include "crypto/base64.h"
#include "rtr/db/vrps.h"
#include "thread/thread_pool.h"

typedef int (*foreach_uri_cb)(struct tal *, struct rpki_uri *, void *);

struct tal {
	char const *file_name;
	struct uri_list ta;
	unsigned char *spki; /* Decoded; not base64. */
	size_t spki_len;
};

struct validation_thread {
	/* TAL file name */
	char *tal_file;
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
	struct threads_list *threads;
};

static int
read_uris(struct line_file *lfile, struct uri_list *ta)
{
	char *line;
	int error;

	error = lfile_read(lfile, &line);
	if (error)
		return error;

	if (line == NULL)
		return pr_op_err("TAL file is empty.");
	if (strcmp(line, "") == 0) {
		free(line);
		return pr_op_err("There's no URI in the first line of the TAL.");
	} else if (strncmp(line, "#", 1) == 0) {
		/* More comments expected, or an URI */
		do {
			free(line); /* Ignore the comment */
			error = lfile_read(lfile, &line);
			if (error)
				return error;
			if (line == NULL)
				return pr_op_err("TAL file ended prematurely. (Expected more comments or an URI list.)");
			if (strcmp(line, "") == 0) {
				free(line);
				return pr_op_err("TAL file comments syntax error. (Expected more comments or an URI list.)");
			}
			/* Not a comment, probably the URI(s) */
			if (strncmp(line, "#", 1) != 0)
				break;
		} while (true);
	}

	do {
		error = uris_add_str(ta, line, URI_TYPE_VERSATILE);
		if (error)
			return error;

		error = lfile_read(lfile, &line);
		if (error)
			return error;

		if (line == NULL)
			return pr_op_err("TAL file ended prematurely. (Expected URI list, blank line and public key.)");
	} while (strcmp(line, "") != 0);

	free(line);
	return 0;
}

static size_t
get_spki_orig_size(struct line_file *lfile)
{
	struct stat st;
	size_t result;

	/* TODO excuse me? Where's the errno validation? */
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
			pr_op_errno(error,
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
	if (offset != new_size) {
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

	error = lfile_open(file_name, &lfile);
	if (error) {
		pr_op_errno(error, "Error opening file '%s'", file_name);
		goto fail4;
	}

	tal = malloc(sizeof(struct tal));
	if (tal == NULL) {
		error = pr_enomem();
		goto fail3;
	}

	tal->file_name = file_name;
	uris_init(&tal->ta);
	error = read_uris(lfile, &tal->ta);
	if (error)
		goto fail1;
	error = read_spki(lfile, tal);
	if (error)
		goto fail1;

	lfile_close(lfile);
	*result = tal;
	return 0;

fail1:	uris_cleanup(&tal->ta);
	free(tal);
fail3:	lfile_close(lfile);
fail4:	return error;
}

void
tal_destroy(struct tal *tal)
{
	if (tal == NULL)
		return;

	uris_cleanup(&tal->ta);
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
 * point to a successfully downloaded Trust Anchor.
 */
static int
handle_ta(struct rpki_uri *uri)
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
	 * TODO (aaaa) comment outdated, "public key not fatal" not implemented
	 *
	 * A "hard error" is any other error.
	 */

	struct validation *state;
	struct cert_stack *certstack;
	struct deferred_cert deferred;
	int error;

	pr_val_debug("Trust Anchor '%s' {", uri_val_get_printable(uri));

	if (!uri_is_certificate(uri)) {
		error = pr_op_err("TAL URI does not point to a certificate. (Expected .cer, got '%s')",
		    uri_op_get_printable(uri));
		goto fail;
	}

	state = state_retrieve();

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
end:	pr_val_debug("}");
	return error;
}

static void
do_file_validation(void *thread_arg)
{
	struct validation_thread *thread = thread_arg;
	struct tal *tal;
	struct rpki_uri *ta;
	struct validation_handler validation_handler;
	int error;

	fnstack_init();
	fnstack_push(thread->tal_file);

	error = tal_load(thread->tal_file, &tal);
	if (error)
		goto undo_fnstack;

	ta = uris_download(&tal->ta);
	if (ta == NULL) {
		error = -ESRCH;
		goto undo_tal;
	}

	validation_handler.handle_roa_v4 = handle_roa_v4;
	validation_handler.handle_roa_v6 = handle_roa_v6;
	validation_handler.handle_router_key = handle_router_key;
	validation_handler.arg = thread->arg;
	error = validation_prepare(tal, &validation_handler);
	if (error)
		goto undo_tal;

	error = handle_ta(ta);

	validation_destroy();
undo_tal:
	tal_destroy(tal);
undo_fnstack:
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
	int error;

	thread = malloc(sizeof(struct validation_thread));
	if (thread == NULL)
		return pr_enomem();

	thread->tal_file = strdup(tal_file);
	if (thread->tal_file == NULL) {
		error = pr_enomem();
		goto free_thread;
	}
	thread->arg = t_param->db;
	thread->exit_status = -EINTR;

	error = thread_pool_push(t_param->pool, thread->tal_file,
	    do_file_validation, thread);
	if (error) {
		pr_op_err("Couldn't push a thread to do files validation");
		goto free_tal_file;
	}

	SLIST_INSERT_HEAD(t_param->threads, thread, next);
	return 0;

free_tal_file:
	free(thread->tal_file);
free_thread:
	free(thread);
	return error;
}

int
perform_standalone_validation(struct thread_pool *pool, struct db_table *table)
{
	struct tal_param *param;
	struct threads_list threads;
	struct validation_thread *thread;
	int error, t_error;

	param = malloc(sizeof(struct tal_param));
	if (param == NULL)
		return pr_enomem();

	SLIST_INIT(&threads);

	param->pool = pool;
	param->db = table;
	param->threads = &threads;

	error = process_file_or_dir(config_get_tal(), ".tal", true,
	    __do_file_validation, param);
	if (error) {
		/* End all thread data */
		while (!SLIST_EMPTY(&threads)) {
			thread = threads.slh_first;
			SLIST_REMOVE_HEAD(&threads, next);
			thread_destroy(thread);
		}
		free(param);
		return error;
	}

	/* Wait for all */
	thread_pool_wait(pool);

	t_error = 0;
	while (!SLIST_EMPTY(&threads)) {
		thread = threads.slh_first;
		SLIST_REMOVE_HEAD(&threads, next);
		if (thread->exit_status) {
			t_error = thread->exit_status;
			pr_op_warn("Validation from TAL '%s' yielded error, discarding any other validation results.",
			    thread->tal_file);
		}
		thread_destroy(thread);
	}

	free(param);

	/* If one thread has errors, we can't keep the resulting table. */
	return t_error;
}
