#include "types/vthread.h"

#include "alloc.h"
#include "config.h"

struct validation_thread *
vthreads_create(void)
{
	unsigned int n;
	struct validation_thread *result;
	unsigned int t;

	n = config_get_validation_thread_count();
	result = pcalloc(n, sizeof(struct validation_thread));

#ifdef THREADS_SHARE_VALIDATION_PAYLOAD
	result[0].tbl = db_table_create();
	for (t = 1; t < tcount; t++)
		result[t].tbl = result[0].tbl;
#else
	for (t = 0; t < n; t++)
		result[t].tbl = db_table_create();
#endif

	return result;
}

struct db_table *
vthreads_commit(struct validation_thread *vts)
{
	unsigned int n, t;
	struct db_table *result;

	n = config_get_validation_thread_count();

	result = vts[0].tbl;
	vts[0].tbl = NULL;

	for (t = 1; t < n; t++) {
#ifndef THREADS_SHARE_VALIDATION_PAYLOAD
		if (db_table_join(result, vts[t].tbl) != 0) {
			db_table_destroy(result);
			return NULL;
		}
		db_table_destroy(vts[t].tbl);
#endif
		vts[t].tbl = NULL;
	}

	return result;
}

void
vthreads_destroy(struct validation_thread *vts)
{
#ifdef THREADS_SHARE_VALIDATION_PAYLOAD
	db_table_destroy(vts[0]->tbl);
#else
	unsigned int n, t;

	n = config_get_validation_thread_count();
	for (t = 0; t < n; t++)
		db_table_destroy(vts[t].tbl);
#endif

	free(vts);
}
