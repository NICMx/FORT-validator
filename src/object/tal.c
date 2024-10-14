#include "object/tal.h"

#include <ctype.h>
#include <sys/queue.h>
#include <time.h>

#include "base64.h"
#include "cache.h"
#include "common.h"
#include "config.h"
#include "file.h"
#include "log.h"
#include "object/certificate.h"
#include "thread_var.h"
#include "types/path.h"
#include "types/str.h"
#include "types/url.h"

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

		if (url_is_https(fc) || url_is_rsync(fc))
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

/* @file_path is expected to outlive @tal. */
static int
tal_init(struct tal *tal, char const *file_path)
{
	struct file_contents file;
	int error;

	error = file_load(file_path, &file, false);
	if (error)
		return error;

	tal->file_name = path_filename(file_path);

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

static void
__do_file_validation(struct validation_thread *thread)
{
	struct tal tal;
	struct validation_handler collector;
	struct db_table *db;
	struct validation *state;
	char **url;
	struct cache_mapping map;

	thread->error = tal_init(&tal, thread->tal_file);
	if (thread->error)
		return;

	collector.handle_roa_v4 = handle_roa_v4;
	collector.handle_roa_v6 = handle_roa_v6;
	collector.handle_router_key = handle_router_key;
	collector.arg = db = db_table_create();

	thread->error = validation_prepare(&state, &tal, &collector);
	if (thread->error) {
		db_table_destroy(db);
		goto end1;
	}

	ARRAYLIST_FOREACH(&tal.urls, url) {
		map.url = *url;
		map.path = cache_refresh_url(*url);
		if (!map.path)
			continue;
		if (traverse_tree(&map, state) != 0)
			continue;
		goto end2; /* Happy path */
	}

	ARRAYLIST_FOREACH(&tal.urls, url) {
		map.url = *url;
		map.path = cache_fallback_url(*url);
		if (!map.path)
			continue;
		if (traverse_tree(&map, state) != 0)
			continue;
		goto end2; /* Happy path */
	}

	pr_op_err("None of the TAL URIs yielded a successful traversal.");
	thread->error = EINVAL;
	db_table_destroy(db);
	db = NULL;

end2:	thread->db = db;
	validation_destroy(state);
end1:	tal_cleanup(&tal);
}

static void *
do_file_validation(void *arg)
{
	struct validation_thread *thread = arg;
	time_t start, finish;

	start = time(NULL);

	fnstack_init();
	fnstack_push(thread->tal_file);

	__do_file_validation(thread);

	fnstack_cleanup();

	finish = time(NULL);
	if (start != ((time_t) -1) && finish != ((time_t) -1))
		pr_op_debug("The %s tree took %.0lf seconds.",
		    path_filename(thread->tal_file),
		    difftime(finish, start));
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
	int error;
	int tmperr;

	error = cache_prepare();
	if (error)
		return NULL;

	/* TODO (fine) Maybe don't spawn threads if there's only one TAL */
	if (foreach_file(config_get_tal(), ".tal", true, spawn_tal_thread,
			 &threads) != 0) {
		while (!SLIST_EMPTY(&threads)) {
			thread = SLIST_FIRST(&threads);
			SLIST_REMOVE_HEAD(&threads, next);
			thread_destroy(thread);
		}

		/*
		 * Commit even on failure, as there's no reason to throw away
		 * something we recently downloaded if it's marked as valid.
		 */
		goto end;
	}

	/* Wait for all */
	while (!SLIST_EMPTY(&threads)) {
		thread = SLIST_FIRST(&threads);
		tmperr = pthread_join(thread->pid, NULL);
		if (tmperr)
			pr_crit("pthread_join() threw '%s' on the '%s' thread.",
			    strerror(tmperr), thread->tal_file);
		SLIST_REMOVE_HEAD(&threads, next);
		if (thread->error) {
			error = thread->error;
			pr_op_warn("Validation from TAL '%s' yielded '%s'; "
			    "discarding all validation results.",
			    thread->tal_file, strerror(abs(error)));
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

	/* If at least one thread had a fatal error, the table is unusable. */
	if (error) {
		db_table_destroy(db);
		db = NULL;
	}

end:	cache_commit();
	return db;
}
