#include "object/tal.h"

#include <ctype.h>
#include <errno.h>
#include <openssl/evp.h>
#include <sys/queue.h>
#include <time.h>

#include "alloc.h"
#include "base64.h"
#include "cache.h"
#include "cert_stack.h"
#include "common.h"
#include "config.h"
#include "file.h"
#include "log.h"
#include "object/certificate.h"
#include "rtr/db/vrps.h"
#include "state.h"
#include "thread_var.h"
#include "types/str.h"
#include "validation_handler.h"

typedef int (*foreach_map_cb)(struct tal *, struct cache_mapping *, void *);

struct tal {
	char const *file_name;
	struct strlist urls;
	unsigned char *spki; /* Decoded; not base64. */
	size_t spki_len;
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

static char *
find_newline(char *str)
{
	for (; true; str++) {
		if (str[0] == '\0')
			return NULL;
		if (str[0] == '\n')
			return str;
		if (str[0] == '\r' && str[1] == '\n')
			return str;
	}
}

static bool
is_blank(char const *str)
{
	for (; str[0] != '\0'; str++)
		if (!isspace(str[0]))
			return false;
	return true;
}

static int
read_content(char *fc /* File Content */, struct tal *tal)
{
	char *nl; /* New Line */
	bool cr; /* Carriage return */

	/* Comment section */
	while (fc[0] == '#') {
		nl = strchr(fc, '\n');
		if (!nl)
			goto premature;
		fc = nl + 1;
	}

	/* URI section */
	do {
		nl = find_newline(fc);
		if (!nl)
			goto premature;

		cr = (nl[0] == '\r');
		nl[0] = '\0';
		if (is_blank(fc))
			break;

		// XXX no longer validating schema
		strlist_add(&tal->urls, pstrdup(fc));

		fc = nl + cr + 1;
		if (*fc == '\0')
			return pr_op_err("The TAL seems to be missing the public key.");
	} while (true);

	if (tal->urls.len == 0)
		return pr_op_err("There seems to be an empty/blank line before the end of the URI section.");

	/* subjectPublicKeyInfo section */
	if (!base64_decode(nl + cr + 1, 0, &tal->spki, &tal->spki_len))
		return pr_op_err("Cannot decode the public key.");

	return 0;

/* This label requires fc to make sense */
premature:
	return pr_op_err("The TAL seems to end prematurely at line '%s'.", fc);
}

/**
 * @file_name is expected to outlive the result.
 */
static int
tal_init(struct tal *tal, char const *file_path)
{
	char const *file_name;
	struct file_contents file;
	int error;

	error = file_load(file_path, &file, false);
	if (error)
		return error;

	file_name = strrchr(file_path, '/');
	file_name = (file_name != NULL) ? (file_name + 1) : file_path;
	tal->file_name = file_name;

	strlist_init(&tal->urls);
	error = read_content((char *)file.buffer, tal);
	if (error)
		strlist_cleanup(&tal->urls);

	file_free(&file);
	return error;
}

static void
tal_cleanup(struct tal *tal)
{
	free(tal->spki);
	strlist_cleanup(&tal->urls);
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

/**
 * Performs the whole validation walkthrough on the @map mapping, which is
 * assumed to have been extracted from TAL @tal.
 */
static int
handle_tal_map(struct tal *tal, struct cache_mapping *map, struct db_table *db)
{
	struct validation_handler validation_handler;
	struct validation *state;
	struct cert_stack *certstack;
	struct deferred_cert deferred;
	int error;

	pr_val_debug("TAL URI '%s' {", map_val_get_printable(map));

	validation_handler.handle_roa_v4 = handle_roa_v4;
	validation_handler.handle_roa_v6 = handle_roa_v6;
	validation_handler.handle_router_key = handle_router_key;
	validation_handler.arg = db;

	error = validation_prepare(&state, tal, &validation_handler);
	if (error)
		return ENSURE_NEGATIVE(error);

	if (!map_has_extension(map, ".cer")) {
		pr_op_err("TAL URI does not point to a certificate. (Expected .cer, got '%s')",
		    map_op_get_printable(map));
		error = EINVAL;
		goto end;
	}

	/* Handle root certificate. */
	error = certificate_traverse(NULL, map);
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
		certificate_traverse(deferred.pp, deferred.map);

		map_refput(deferred.map);
		rpp_refput(deferred.pp);
	} while (true);

end:	validation_destroy(state);
	pr_val_debug("}");
	return error;
}

static int
__handle_tal_map(struct cache_mapping *map, void *arg)
{
	struct handle_tal_args *args = arg;
	return handle_tal_map(&args->tal, map, args->db);
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
	thread->error = cache_download_uri(&args.tal.urls,
	    __handle_tal_map, &args);
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
	int error = 0;
	int tmperr;

	cache_setup();

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
