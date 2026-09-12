#include "object/tal.h"

#include <ctype.h>

#include "base64.h"
#include "config.h"
#include "file.h"
#include "log.h"
#include "object/certificate.h"
#include "report.h"
#include "task.h"
#include "thread_var.h"
#include "types/path.h"
#include "types/vthread.h"

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
parse_tal(struct tal *tal, char *fc /* File Content */)
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
			pr_trc("Ignoring URI '%s': %s", fc, error);
		}

		fc = nl + cr + 1;
		if (*fc == '\0')
			return pr_err("The TAL seems to be missing the public key.");
	} while (true);

	if (tal->urls.len == 0)
		return pr_err("There seems to be an empty/blank line before the end of the URI section.");

	/* subjectPublicKeyInfo section */
	if (!base64_decode(nl + cr + 1, 0, &tal->spki, &tal->spki_len))
		return pr_err("Cannot decode the public key.");

	return 0;

/* This label requires fc to make sense */
premature:
	return pr_err("The TAL seems to end prematurely at line '%s'.", fc);
}

static struct tal *
tal_create(char const *path)
{
	struct tal *tal;
	struct file_contents file;

	if (file_load(path, &file, false) != 0)
		return NULL;

	tal = pzalloc(sizeof(struct tal));
	tal->path = pstrdup(path);
	uris_init(&tal->urls);
	atomic_init(&tal->refcount, 1);

	if (parse_tal(tal, (char *)file.buf) != 0) {
		uris_cleanup(&tal->urls, uri_cleanup);
		free(tal->path);
		free(tal);
		tal = NULL;
	}

	file_free(&file);
	return tal;
}

void
tal_cleanup(struct tal *tal)
{
	if (atomic_fetch_sub(&tal->refcount, 1) == 1) {
		free(tal->spki);
		uris_cleanup(&tal->urls, uri_cleanup);
		free(tal->path);
		free(tal);
	}
}

static int
queue_tal(char const *tal_path, void *arg)
{
	if (task_enqueue_tal(tal_path) < 1) {
		pr_err("Could not enqueue task '%s'; abandoning validation.",
		    tal_path);
		return EINVAL;
	}

	return 0;
}

static validation_verdict
validate_ta(struct validation_thread *vt, struct tal *tal,
    struct cache_mapping const *ta_map)
{
	struct rpki_certificate *ta;
	validation_verdict vv;

	ta = pzalloc(sizeof(struct rpki_certificate));
	map_copy(&ta->map, ta_map);
	ta->tal = tal;
	atomic_fetch_add(&tal->refcount, 1);
	atomic_init(&ta->refcount, 1);

	vv = cer_traverse(vt, ta);

	cer_free(ta);
	return vv;
}

static validation_verdict
try_urls(struct validation_thread *vt, struct tal *tal, char const *proto,
    validation_verdict (*get_querier)(struct uri const *, struct file_querier **))
{
	struct uri *url;
	struct file_querier *querier;
	struct cache_mapping map;
	validation_verdict vv;

	ARRAYLIST_FOREACH(&tal->urls, url) {
		if (!uri_is_proto(url, proto))
			continue;

		querier = NULL;
		vv = get_querier(url, &querier);
		if (vv == VV_BUSY)
			return VV_BUSY;
		if (vv == VV_FAIL)
			continue;

		map.url = *url;
		map.path = (char *)fquerier_map(querier);

		if (!map.path)
			continue; /* Nonexistent fallback */

		vv = validate_ta(vt, tal, &map);
		if (vv == VV_CONTINUE)
			fquerier_commit(querier);

		fquerier_free(querier);

		if (vv == VV_CONTINUE || vv == VV_BUSY)
			return vv;
	}

	pr_trc("TAL: No %.5s URIs succeeded.", proto);
	return VV_FAIL;
}

static validation_verdict
traverse_tal(struct validation_thread *vt, char const *path)
{
	struct tal *tal;
	validation_verdict vv;

	fnstack_push(path);

	tal = tal_create(path);
	if (!tal) {
		vv = VV_FAIL;
		goto end1;
	}

	/* Online attempts */
	pr_trc("Trying HTTP refresh.");
	vv = try_urls(vt, tal, "https:", fquery_refresh_https);
	if (vv != VV_FAIL)
		goto end2;
	pr_trc("Trying rsync refresh.");
	vv = try_urls(vt, tal, "rsync:", fquery_refresh_rsync);
	if (vv != VV_FAIL)
		goto end2;
	/* Offline fallback attempts */
	pr_trc("Trying HTTP fallback.");
	vv = try_urls(vt, tal, "https:", fquery_fallback_https);
	if (vv != VV_FAIL)
		goto end2;
	pr_trc("Trying rsync fallback.");
	vv = try_urls(vt, tal, "rsync:", fquery_fallback_rsync);
	if (vv != VV_FAIL)
		goto end2;

	pr_err("None of the TAL URIs yielded a successful traversal.");
	vv = VV_FAIL;

end2:	tal_cleanup(tal);
end1:	fnstack_pop();
	return vv;
}

static void *
pick_up_work(void *arg)
{
	struct validation_task *task = NULL;
	struct validation_thread *vt = arg;
	validation_verdict vv;

	while ((task = task_dequeue(task)) != NULL) {
		pr_trc("Dequeued task: %s", task_name(task));

		switch (task->type) {
		case VTT_RPP:
			vv = cer_traverse(vt, task->u.ca);
			if (vv == VV_BUSY) {
				task_requeue_dormant(task);
				task = NULL;
			}
			break;
		case VTT_TAL:
			vv = traverse_tal(vt, task->u.tal);
			if (vv == VV_BUSY) {
				task_requeue_dormant(task);
				task = NULL;
			} else if (vv == VV_FAIL) {
				task_cancel();
			}
			break;
		default:
			vv = VV_FAIL;
		}

		pr_trc("Task ended. Status: %s", vv);
	}

	return NULL;
}

struct db_table *
perform_standalone_validation(void)
{
	struct validation_thread *vts; /* array */
	unsigned int tcount;
	unsigned int t;
	struct db_table *result;
	int error;

	if (cache_prepare() != 0)
		return NULL;

	result = NULL;
	task_start();

	if (foreach_file(config_get_tal(), ".tal", true, queue_tal, NULL) != 0)
		goto end;

	if (report_enable() != 0)
		goto end;

	vts = vthreads_create();
	tcount = config_get_validation_thread_count();

	for (t = 0; t < tcount; t++) {
		error = pthread_create(&vts[t].id, NULL, pick_up_work, &vts[t]);
		if (error)
			pr_panic("pthread_create(%u) failed: %s",
			    t, strerror(error));
	}

	for (t = 0; t < tcount; t++) {
		error = pthread_join(vts[t].id, NULL);
		if (error)
			pr_panic("pthread_join(%u) failed: %s",
			    t, strerror(error));
	}

	if (!task_stopped()) {
		result = vthreads_commit(vts); /* Can return NULL! */

//		// FIXME
//		stats_set_tal_vrps(thread->tal_file, "ipv4",
//		    db_table_roa_count_v4(thread->db));
//		stats_set_tal_vrps(thread->tal_file, "ipv6",
//		    db_table_roa_count_v6(thread->db));
	}

	vthreads_destroy(vts);
	report_disable();
	fnstack_cleanup(); // XXX there's no init?
	cache_commit();
end:	task_stop();
	return result;
}
