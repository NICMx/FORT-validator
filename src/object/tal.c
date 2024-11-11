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
#include "task.h"
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

static int
validate_ta(struct tal *tal, struct cache_mapping const *ta_map)
{
	struct rpki_certificate *ta;
	int error;

	ta = pzalloc(sizeof(struct rpki_certificate));
	map_copy(&ta->map, ta_map);
	ta->tal = tal;
	atomic_init(&ta->refcount, 1);

	error = certificate_traverse(ta);

	rpki_certificate_free(ta);
	return error;
}

static int
traverse_tal(char const *tal_path, void *arg)
{
	struct tal tal;
	char **url;
	struct cache_mapping map;
	int error;

	fnstack_push(tal_path);

	error = tal_init(&tal, tal_path);
	if (error)
		goto end1;

	/* Online attempts */
	ARRAYLIST_FOREACH(&tal.urls, url) {
		map.url = *url;
		map.path = cache_refresh_by_url(*url);
		if (!map.path)
			continue;
		if (validate_ta(&tal, &map) != 0)
			continue;
		cache_commit_file(&map);
		goto end2; /* Happy path */
	}

	/* Offline fallback attempts */
	ARRAYLIST_FOREACH(&tal.urls, url) {
		map.url = *url;
		map.path = cache_get_fallback(*url);
		if (!map.path)
			continue;
		if (validate_ta(&tal, &map) != 0)
			continue;
		cache_commit_file(&map);
		goto end2; /* Happy path */
	}

	pr_op_err("None of the TAL URIs yielded a successful traversal.");
	error = EINVAL;

end2:	tal_cleanup(&tal);
end1:	fnstack_pop();
	return error;
}

static void *
pick_up_work(void *arg)
{
	struct validation_task *task = NULL;

	while ((task = task_dequeue(task)) != NULL) {
		if (certificate_traverse(task->ca) == EBUSY) {
			task_requeue_busy(task);
			task = NULL;
		}
	}

	return NULL;
}

int
perform_standalone_validation(void)
{
	pthread_t threads[5]; // XXX variabilize
	array_index t, t2;
	int error;

	error = cache_prepare();
	if (error)
		return error;
	fnstack_init();
	task_start();

	if (foreach_file(config_get_tal(), ".tal", true, traverse_tal, NULL)!=0)
		goto end;

	for (t = 0; t < 5; t++) {
		error = pthread_create(&threads[t], NULL, pick_up_work, NULL);
		if (error) {
			pr_op_err("Could not spawn validation thread %zu: %s",
			    t, strerror(error));
			break;
		}
	}

	if (t == 0) {
		pick_up_work(NULL);
		error = 0;
	} else for (t2 = 0; t2 < t; t2++) {
		error = pthread_join(threads[t2], NULL);
		if (error)
			pr_crit("pthread_join(%zu) failed: %s",
			    t2, strerror(error));
	}

end:	task_stop();
	fnstack_cleanup();
	/*
	 * Commit even on failure, as there's no reason to throw away something
	 * we might have recently downloaded if it managed to be marked valid.
	 */
	cache_commit();
	return error;
}
