#include "object/tal.h"

#include <errno.h>
#include <openssl/evp.h>
#include <sys/queue.h>
#include <time.h>

#include "alloc.h"
#include "cert_stack.h"
#include "common.h"
#include "config.h"
#include "line_file.h"
#include "log.h"
#include "state.h"
#include "thread_var.h"
#include "validation_handler.h"
#include "cache/tmp.h"
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

	struct rpki_cache *cache;
};

struct validation_thread {
	pthread_t pid;
	char *tal_file; /* TAL file name */
	struct db_table *db;
	int error;
	/* This should also only be manipulated by the parent thread. */
	SLIST_ENTRY(validation_thread) next;
};

/* List of threads, one per TAL file */
SLIST_HEAD(threads_list, validation_thread);

struct handle_tal_args {
	struct tal tal;
	struct db_table *db;
};

static int
add_uri(struct uri_list *uris, char const *tal, char *uri)
{
	struct rpki_uri *new = NULL;
	int error;

	if (str_starts_with(uri, "rsync://"))
		error = uri_create(&new, tal, UT_RSYNC, false, NULL, uri);
	else if (str_starts_with(uri, "https://"))
		error = uri_create(&new, tal, UT_HTTPS, false, NULL, uri);
	else
		return pr_op_err("TAL has non-RSYNC/HTTPS URI: %s", uri);
	if (error)
		return error;

	uris_add(uris, new);
	return 0;
}

static int
read_uris(struct line_file *lfile, char const *tal, struct uri_list *uris)
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
		error = add_uri(uris, tal, uri);
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
	size_t size;
	int error;

	size = get_spki_alloc_size(lfile);
	tal->spki = pmalloc(size);

	tmp = NULL;
	error = base64_sanitize(lfile, &tmp);
	if (error)
		goto revert_spki;

	encoded = BIO_new_mem_buf(tmp, -1);
	if (encoded == NULL) {
		error = op_crypto_err("BIO_new_mem_buf() returned NULL.");
		goto revert_tmp;
	}

	if (!base64_decode(encoded, tal->spki, true, size, &tal->spki_len)) {
		error = op_crypto_err("Cannot decode SPKI.");
		goto revert_encoded;
	}

	free(tmp);
	BIO_free(encoded);
	return 0;

revert_encoded:
	BIO_free(encoded);
revert_tmp:
	free(tmp);
revert_spki:
	free(tal->spki);
	return error;
}

/**
 * @file_name is expected to outlive the result.
 */
static int
tal_init(struct tal *tal, char const *file_path)
{
	struct line_file *lfile;
	char const *file_name;
	int error;

	lfile = NULL; /* Warning shutupper */
	error = lfile_open(file_path, &lfile);
	if (error) {
		pr_op_err("Error opening file '%s': %s", file_path,
		    strerror(abs(error)));
		return error;
	}

	file_name = strrchr(file_path, '/');
	file_name = (file_name != NULL) ? (file_name + 1) : file_path;

	tal->file_name = file_name;
	uris_init(&tal->uris);
	error = read_uris(lfile, file_name, &tal->uris);
	if (error)
		goto fail;
	error = read_spki(lfile, tal);
	if (error)
		goto fail;

	tal->cache = cache_create(file_name);

	lfile_close(lfile);
	return 0;

fail:
	uris_cleanup(&tal->uris);
	lfile_close(lfile);
	return error;
}

static void
tal_cleanup(struct tal *tal)
{
	cache_destroy(tal->cache);
	free(tal->spki);
	uris_cleanup(&tal->uris);
}

char const *
tal_get_file_name(struct tal *tal)
{
	return (tal != NULL) ? tal->file_name : NULL;
}

void
tal_get_spki(struct tal *tal, unsigned char const **buffer, size_t *len)
{
	*buffer = tal->spki;
	*len = tal->spki_len;
}

struct rpki_cache *
tal_get_cache(struct tal *tal)
{
	return tal->cache;
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
	return handle_tal_uri(&args->tal, uri, args->db);
}

static void *
do_file_validation(void *arg)
{
	struct validation_thread *thread = arg;
	struct handle_tal_args args;
	time_t start, finish;

	start = time(NULL);

	fnstack_init();
	fnstack_push(thread->tal_file);

	thread->error = tal_init(&args.tal, thread->tal_file);
	if (thread->error)
		goto end;

	args.db = db_table_create();
	thread->error = cache_download_alt(args.tal.cache, &args.tal.uris,
	    false, __handle_tal_uri, &args);
	if (thread->error) {
		pr_op_err("None of the URIs of the TAL '%s' yielded a successful traversal.",
		    thread->tal_file);
		db_table_destroy(args.db);
	} else {
		thread->db = args.db;
	}

	tal_cleanup(&args.tal);
end:	fnstack_cleanup();

	finish = time(NULL);
	if (start != ((time_t) -1) && finish != ((time_t) -1))
		pr_op_debug("The %s tree took %.0lf seconds.",
		    args.tal.file_name, difftime(finish, start));
	return NULL;
}

static void
thread_destroy(struct validation_thread *thread)
{
	free(thread->tal_file);
	db_table_destroy(thread->db);
	free(thread);
}

/* Creates a thread for the @tal_file TAL */
static int
spawn_tal_thread(char const *tal_file, void *arg)
{
	struct threads_list *threads = arg;
	struct validation_thread *thread;
	int error;

	thread = pmalloc(sizeof(struct validation_thread));

	thread->tal_file = pstrdup(tal_file);
	thread->db = NULL;
	thread->error = -EINTR;
	SLIST_INSERT_HEAD(threads, thread, next);

	error = pthread_create(&thread->pid, NULL, do_file_validation, thread);
	if (error) {
		pr_op_err("Could not spawn validation thread for %s: %s",
		    tal_file, strerror(error));
		free(thread->tal_file);
		free(thread);
	}

	return error;
}

struct db_table *
perform_standalone_validation(void)
{
	struct threads_list threads = SLIST_HEAD_INITIALIZER(threads);
	struct validation_thread *thread;
	struct db_table *db = NULL;
	int error, tmperr;

	cache_setup();

	error = init_tmpdir();
	if (error) {
		pr_val_err("Cannot initialize the cache's temporal directory: %s",
		    strerror(error));
		return NULL;
	}

	/* TODO (fine) Maybe don't spawn threads if there's only one TAL */
	if (foreach_file(config_get_tal(), ".tal", true, spawn_tal_thread,
			 &threads) != 0) {
		while (!SLIST_EMPTY(&threads)) {
			thread = SLIST_FIRST(&threads);
			SLIST_REMOVE_HEAD(&threads, next);
			thread_destroy(thread);
		}
		return NULL;
	}

	/* Wait for all */
	while (!SLIST_EMPTY(&threads)) {
		thread = SLIST_FIRST(&threads);
		tmperr = pthread_join(thread->pid, NULL);
		if (tmperr)
			pr_crit("pthread_join() threw %d (%s) on the '%s' thread.",
			    tmperr, strerror(tmperr), thread->tal_file);
		SLIST_REMOVE_HEAD(&threads, next);
		if (thread->error) {
			error = thread->error;
			pr_op_warn("Validation from TAL '%s' yielded error %d (%s); discarding all validation results.",
			    thread->tal_file, error, strerror(abs(error)));
		}

		if (!error) {
			if (db == NULL) {
				db = thread->db;
				thread->db = NULL;
			} else {
				error = db_table_join(db, thread->db);
			}
		}

		thread_destroy(thread);
	}

	cache_teardown();

	/* If one thread has errors, we can't keep the resulting table. */
	if (error) {
		db_table_destroy(db);
		db = NULL;
	}

	return db;
}
