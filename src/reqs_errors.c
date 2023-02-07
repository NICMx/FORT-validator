#include "reqs_errors.h"

#include <pthread.h>
#include <syslog.h>
#include <time.h>

#include "data_structure/uthash.h"
#include "common.h"
#include "config.h"
#include "log.h"
#include "thread_var.h"

/*
 * Only log messages of repositories whose level is less than or equal to this.
 *
 * Level 0 is "top level", mostly used by the root CAs (trust anchors) and RIRs
 * before RPKI servers delegation.
 *
 * Eg. The URIs will have this level (data according to current RPKI state):
 * rsync://repository.lacnic.net/    [level 0]
 * rsync://rpki-repo.registro.br/    [level 1]
 *
 * rsync://rpki.ripe.net/            [level 0]
 * rsync://ca.rg.net/                [level 1]
 * rsync://cc.rg.net/                [level 2]
 */
#define LOG_REPO_LEVEL 0

struct error_uri {
	/* Key */
	char *uri;
	/* Date when the first attempt was made */
	time_t first_attempt;
	/* Related URI (points to a key of another element) */
	char *uri_related;
	/* Refered by (where this.uri == that.uri_related) */
	char *ref_by;
	/* Log the summary */
	bool log_summary;
	UT_hash_handle hh;
};

static struct error_uri *err_uris_db;

/* Prepare for multithreading. */
static pthread_rwlock_t db_lock;

static int
error_uri_create(char const *uri, struct error_uri **err_uri)
{
	struct error_uri *tmp;
	int error;

	tmp = malloc(sizeof(struct error_uri));
	if (tmp == NULL)
		return pr_enomem();

	/* Needed by uthash */
	memset(tmp, 0, sizeof(struct error_uri));

	tmp->uri = strdup(uri);
	if (tmp->uri == NULL) {
		error = pr_enomem();
		goto release_tmp;
	}

	error = get_current_time(&tmp->first_attempt);
	if (error)
		goto release_uri;

	tmp->log_summary = false;
	tmp->uri_related = NULL;
	tmp->ref_by = NULL;

	*err_uri = tmp;
	return 0;
release_uri:
	free(tmp->uri);
release_tmp:
	free(tmp);
	return error;
}

static void
error_uri_destroy(struct error_uri *err_uri)
{
	free(err_uri->uri);
	free(err_uri);
}

int
reqs_errors_init(void)
{
	int error;

	error = pthread_rwlock_init(&db_lock, NULL);
	if (error) {
		pr_op_err("pthread_rwlock_init() errored: %s", strerror(error));
		return error;
	}

	err_uris_db = NULL;

	return 0;
}

void
reqs_errors_cleanup(void)
{
	/* Remove all the uris */
	struct error_uri *node, *tmp;

	HASH_ITER(hh, err_uris_db, node, tmp) {
		HASH_DEL(err_uris_db, node);
		error_uri_destroy(node);
	}

	pthread_rwlock_destroy(&db_lock); /* Nothing to do with error code */
}

static struct error_uri *
find_error_uri(char const *search, bool lock)
{
	struct error_uri *found;

	if (lock)
		rwlock_read_lock(&db_lock);
	HASH_FIND_STR(err_uris_db, search, found);
	if (lock)
		rwlock_unlock(&db_lock);

	return found;
}

static void
set_working_repo(struct error_uri *err_uri)
{
	struct error_uri *ref;
	char const *work_uri;

	work_uri = working_repo_peek();
	if (work_uri == NULL)
		return;

	ref = find_error_uri(work_uri, true);
	if (ref == NULL)
		return;

	err_uri->uri_related = ref->uri;
	ref->ref_by = err_uri->uri;
}

int
reqs_errors_add_uri(char const *uri)
{
	struct error_uri *new_uri, *found_uri;
	int error;

	/* Don't overwrite if it already exists */
	found_uri = find_error_uri(uri, true);
	if (found_uri != NULL)
		return 0;

	new_uri = NULL;
	error = error_uri_create(uri, &new_uri);
	if (error)
		return error;

	set_working_repo(new_uri);

	/*
	 * Check if this will always be logged, in that case the summary will
	 * be logged also if the level must be logged.
	 */
	if (config_get_stale_repository_period() == 0)
		new_uri->log_summary =
		    (working_repo_peek_level() <= LOG_REPO_LEVEL);

	rwlock_write_lock(&db_lock);
	HASH_ADD_STR(err_uris_db, uri, new_uri);
	rwlock_unlock(&db_lock);

	return 0;
}

void
reqs_errors_rem_uri(char const *uri)
{
	struct error_uri *found_uri;
	struct error_uri *tmp;
	char *ref_uri;

	rwlock_write_lock(&db_lock);
	found_uri = find_error_uri(uri, false);
	if (found_uri == NULL) {
		rwlock_unlock(&db_lock);
		return;
	}

	while (found_uri->uri_related != NULL) {
		tmp = find_error_uri(found_uri->uri_related, false);
		if (tmp == NULL)
			break;
		found_uri = tmp;
	}

	do {
		ref_uri = found_uri->ref_by;
		HASH_DELETE(hh, err_uris_db, found_uri);
		error_uri_destroy(found_uri);
		if (ref_uri == NULL)
			break;
		HASH_FIND_STR(err_uris_db, ref_uri, found_uri);
		if (found_uri == NULL)
			break;
	} while (true);
	rwlock_unlock(&db_lock);
}

int
reqs_errors_foreach(reqs_errors_cb cb, void *arg)
{
	struct error_uri *node, *tmp;
	int error;

	rwlock_read_lock(&db_lock);
	HASH_ITER(hh, err_uris_db, node, tmp) {
		error = cb(node->uri, arg);
		if (error) {
			rwlock_unlock(&db_lock);
			return error;
		}
	}
	rwlock_unlock(&db_lock);

	return 0;
}

bool
reqs_errors_log_uri(char const *uri)
{
	struct error_uri *node;
	time_t now;
	unsigned int config_period;
	int error;

	if (log_op_enabled(LOG_DEBUG))
		return true;

	if (working_repo_peek_level() > LOG_REPO_LEVEL)
		return false;

	/* Log always? Don't care if the URI exists yet or not */
	config_period = config_get_stale_repository_period();
	if (config_period == 0)
		return true;

	node = find_error_uri(uri, true);
	if (node == NULL)
		return false;

	now = 0;
	error = get_current_time(&now);
	if (error)
		return false;

	node->log_summary = (difftime(now, node->first_attempt) >=
	    (double)config_period);

	return node->log_summary;
}

/*
 * Log a summary of the error'd servers.
 */
void
reqs_errors_log_summary(void)
{
	/* Remove all the uris */
	struct error_uri *node, *tmp;
	time_t now;
	char *str_time;
	bool first;
	int error;

	first = true;
	now = 0;
	error = get_current_time(&now);
	if (error)
		return;

	rwlock_read_lock(&db_lock);
	HASH_ITER(hh, err_uris_db, node, tmp) {
		if (!node->log_summary)
			continue;
		if (first) {
			pr_op_warn("The following repositories URIs couldn't be fetched (it can be a local issue or a server issue), please review previous log messages related to such URIs/servers:");
			first = false;
		}
		str_time = asctime(localtime(&node->first_attempt));
		if (strrchr(str_time, '\n') != NULL) {
			*(str_time + strlen(str_time) - 1) = ' ';
		}
		pr_op_warn("- '%s': can't be downloaded since %s", node->uri,
		    str_time);
	}

	rwlock_unlock(&db_lock);
}
