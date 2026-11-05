#include "types/vthread.h"

#include "alloc.h"
#include "config.h"

struct validation_thread *
vthreads_create(void)
{
	unsigned int n, t;
	struct validation_thread *result;

	n = fortcfg.thread_pool.validation.max;
	result = pcalloc(n, sizeof(struct validation_thread));

#ifdef THREADS_SHARE_VALIDATION_PAYLOAD
	result[0].tbl = vpt_create();
	for (t = 1; t < n; t++)
		result[t].tbl = result[0].tbl;
#else
	for (t = 0; t < n; t++)
		result[t].tbl = vpt_create();
#endif

	return result;
}

struct vp_table *
vthreads_commit(struct validation_thread *vts)
{
	unsigned int t;
	struct vp_table *result;

	result = vts[0].tbl;
	vts[0].tbl = NULL;

	for (t = 1; t < fortcfg.thread_pool.validation.max; t++) {
#ifndef THREADS_SHARE_VALIDATION_PAYLOAD
		if (vpt_join(result, vts[t].tbl) != 0) {
			vpt_destroy(result);
			return NULL;
		}
		vpt_destroy(vts[t].tbl);
#endif
		vts[t].tbl = NULL;
	}

	return result;
}

void
vthreads_destroy(struct validation_thread *vts)
{
#ifdef THREADS_SHARE_VALIDATION_PAYLOAD
	vpt_destroy(vts[0]->tbl);
#else
	unsigned int t;

	for (t = 0; t < fortcfg.thread_pool.validation.max; t++)
		vpt_destroy(vts[t].tbl);
#endif

	free(vts);
}
