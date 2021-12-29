#include "rpp/rpp_dl_status.h"

#include "log.h"
#include "thread_var.h"
#include "data_structure/uthash_nonfatal.h"

struct visited_rpp {
	struct rpki_uri *uri;
	enum rpp_download_status status;
	UT_hash_handle hh;
};

struct rpp_dl_status_db {
	struct visited_rpp *table;
};

static struct rpp_dl_status_db *
get_db(void)
{
	struct rpp_dl_status_db *db;

	db = validation_get_rppdb(state_retrieve());
	if (db == NULL)
		pr_crit("Thread has no RPP table");

	return db;
}

struct rpp_dl_status_db *
rdsdb_create(void)
{
	struct rpp_dl_status_db *result;

	result = malloc(sizeof(struct rpp_dl_status_db));
	if (result == NULL)
		return NULL;

	result->table = NULL;
	return result;
}

void
rdsdb_destroy(struct rpp_dl_status_db *db)
{
	struct visited_rpp *node, *tmp;

	HASH_ITER(hh, db->table, node, tmp) {
		HASH_DEL(db->table, node);
		uri_refput(node->uri);
		free(node);
	}
	free(db);
}

/*
 * Returns the download status (from the current validation cycle) of @uri.
 */
enum rpp_download_status
rdsdb_get(struct rpki_uri *uri)
{
	struct rpp_dl_status_db *db;
	struct visited_rpp *rpp;

	db = get_db();
	HASH_FIND_STR(db->table, uri_get_global(uri), rpp);

	return (rpp != NULL) ? rpp->status : RDS_NOT_YET;
}

/*
 * Remembers @uri's download result code @error during the rest of the current
 * validation cycle.
 */
void
rdsdb_set(struct rpki_uri *uri, int error)
{
	struct rpp_dl_status_db *db;
	struct visited_rpp *new_rpp;
	char const *key;
	size_t key_len;

	if (error == ENOTCHANGED) {
		pr_val_debug("No updates.");
		error = 0;
	}

	db = get_db();

	new_rpp = malloc(sizeof(struct visited_rpp));
	if (new_rpp == NULL) {
		pr_enomem();
		/*
		 * Might end up redownloading, but it's better than returning
		 * error, because caller would interpret that as "WILL end up
		 * redownloading."
		 *
		 * This sucks.
		 *
		 * TODO You should REALLY implement critical enomems already.
		 */
		return;
	}

	new_rpp->status = error ? RDS_ERROR : RDS_SUCCESS;
	new_rpp->uri = uri;
	uri_refget(uri);

	key = uri_get_global(uri);
	key_len = strlen(key);
	HASH_ADD_KEYPTR(hh, db->table, key, key_len, new_rpp);
}
