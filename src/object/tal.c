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
#include "types/uri.h"

struct tal {
	char const *file_name;
	struct uris urls;
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
	struct uri url;
	error_msg error;

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

		error = uri_init(&url, fc);
		if (!error) {
			if (uri_is_https(&url) || uri_is_rsync(&url))
				uris_add(&tal->urls, &url);
			else
				uri_cleanup(&url);
		} else {
			pr_op_debug("Ignoring URI '%s': %s", fc, error);
		}

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

	uris_init(&tal->urls);
	error = read_content((char *)file.buf, tal);
	if (error)
		uris_cleanup(&tal->urls, uri_cleanup);

	file_free(&file);
	return error;
}

static void
tal_cleanup(struct tal *tal)
{
	free(tal->spki);
	uris_cleanup(&tal->urls, uri_cleanup);
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
queue_tal(char const *tal_path, void *arg)
{
	if (task_enqueue_tal(tal_path) < 1) {
		pr_op_err("Could not enqueue task '%s'; abandoning validation.",
		    tal_path);
		return EINVAL;
	}

	return 0;
}

static validation_verdict
validate_ta(struct tal *tal, struct cache_mapping const *ta_map)
{
	struct rpki_certificate *ta;
	validation_verdict vv;

	ta = pzalloc(sizeof(struct rpki_certificate));
	map_copy(&ta->map, ta_map);
	ta->tal = tal;
	atomic_init(&ta->refcount, 1);

	vv = certificate_traverse(ta);

	rpki_certificate_free(ta);
	return vv;
}

static validation_verdict
try_urls(struct tal *tal, bool (*url_is_protocol)(struct uri const *),
    char *(*get_path)(struct uri const *))
{
	struct uri *url;
	struct cache_mapping map;
	validation_verdict vv;

	ARRAYLIST_FOREACH(&tal->urls, url) {
		map.url = *url;
		if (!url_is_protocol(&map.url))
			continue;
		map.path = get_path(url);
		if (!map.path)
			continue;
		vv = validate_ta(tal, &map);
		if (vv == VV_BUSY)
			return VV_BUSY;
		if (vv == VV_FAIL)
			continue;
		cache_commit_file(&map);
		return VV_CONTINUE;
	}

	return VV_FAIL;
}

static validation_verdict
traverse_tal(char const *tal_path)
{
	struct tal tal;
	validation_verdict vv;

	fnstack_push(tal_path);

	if (tal_init(&tal, tal_path) != 0) {
		vv = VV_FAIL;
		goto end1;
	}

	/* Online attempts */
	vv = try_urls(&tal, uri_is_https, cache_refresh_by_url);
	if (vv != VV_FAIL)
		goto end2;
	vv = try_urls(&tal, uri_is_rsync, cache_refresh_by_url);
	if (vv != VV_FAIL)
		goto end2;
	/* Offline fallback attempts */
	vv = try_urls(&tal, uri_is_https, cache_get_fallback);
	if (vv != VV_FAIL)
		goto end2;
	vv = try_urls(&tal, uri_is_rsync, cache_get_fallback);
	if (vv != VV_FAIL)
		goto end2;

	pr_op_err("None of the TAL URIs yielded a successful traversal.");
	vv = VV_FAIL;

end2:	tal_cleanup(&tal);
end1:	fnstack_pop();
	return vv;
}

static void *
pick_up_work(void *arg)
{
	struct validation_task *task = NULL;
	validation_verdict vv;

	while ((task = task_dequeue(task)) != NULL) {
		switch (task->type) {
		case VTT_RPP:
			if (certificate_traverse(task->u.ca) == VV_BUSY) {
				task_requeue_dormant(task);
				task = NULL;
			}
			break;
		case VTT_TAL:
			vv = traverse_tal(task->u.tal);
			if (vv == VV_BUSY) {
				task_requeue_dormant(task);
				task = NULL;
			} else if (vv == VV_FAIL) {
				task_stop();
			}
			break;
		}

	}

	return NULL;
}

int
perform_standalone_validation(void)
{
	pthread_t threads[5]; // XXX variabilize
	array_index t;
	int error;

	error = cache_prepare();
	if (error)
		return error;
	fnstack_init();
	task_start();

	error = foreach_file(config_get_tal(), ".tal", true, queue_tal, NULL);
	if (error)
		goto end;

	/*
	 * From now on, the trees should be considered valid, even if subsequent
	 * certificates fail.
	 * (The roots validated successfully; subtrees are isolated problems.)
	 */

	for (t = 0; t < 5; t++) {
		error = pthread_create(&threads[t], NULL, pick_up_work, NULL);
		if (error)
			pr_crit("pthread_create(%zu) failed: %s",
			    t, strerror(error));
	}

	for (t = 0; t < 5; t++) {
		error = pthread_join(threads[t], NULL);
		if (error)
			pr_crit("pthread_join(%zu) failed: %s",
			    t, strerror(error));
	}

end:	if (task_stop())
		error = EINVAL; /* pick_up_work(), VTT_TAL */
	fnstack_cleanup();
	/*
	 * Commit even on failure, as there's no reason to throw away something
	 * we might have recently downloaded if it managed to be marked valid.
	 */
	cache_commit();
	return error;
}
