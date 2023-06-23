#include "rrdp_objects.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "alloc.h"
#include "log.h"

DEFINE_ARRAY_LIST_FUNCTIONS(deltas_head, struct delta_head, )

void
global_data_init(struct global_data *data)
{
	data->session_id = NULL;
}

void
global_data_cleanup(struct global_data *data)
{
	free(data->session_id);
}

void
doc_data_init(struct doc_data *data)
{
	data->uri = NULL;
	data->hash = NULL;
	data->hash_len = 0;
}

void
doc_data_cleanup(struct doc_data *data)
{
	free(data->hash);
	free(data->uri);
}

/* Do the @cb to the delta head elements from @from_serial to @max_serial */
int
deltas_head_for_each(struct deltas_head *deltas, unsigned long max_serial,
    unsigned long from_serial, delta_head_cb cb, void *arg)
{
	size_t index;
	size_t from;
	int error;

	/* No elements, send error so that the snapshot is processed */
	if (deltas->len == 0) {
		pr_val_warn("There's no delta list to process.");
		return -ENOENT;
	}

	pr_val_debug("Getting RRDP deltas from serial %lu to %lu.", from_serial,
	    max_serial);
	from = deltas->len - (max_serial - from_serial);
	for (index = from; index < deltas->len; index++) {
		error = cb(&deltas->array[index], arg);
		if (error)
			return error;
	}

	return 0;
}

static int
swap_until_sorted(struct delta_head *deltas, unsigned int i,
    unsigned long min, unsigned long max)
{
	unsigned int target_slot;
	struct delta_head tmp;

	while (true) {
		if (deltas[i].serial < min || max < deltas[i].serial) {
			return pr_val_err("Deltas: Serial '%lu' is out of bounds. (min:%lu, max:%lu)",
			    deltas[i].serial, min, max);
		}

		target_slot = deltas[i].serial - min;
		if (i == target_slot)
			return 0;
		if (deltas[target_slot].serial == deltas[i].serial) {
			return pr_val_err("Deltas: Serial '%lu' is not unique.",
			    deltas[i].serial);
		}

		/* Simple swap */
		tmp = deltas[target_slot];
		deltas[target_slot] = deltas[i];
		deltas[i] = tmp;
	}
}

int
deltas_head_sort(struct deltas_head *deltas, unsigned long max_serial)
{
	unsigned long min_serial;
	struct delta_head *cursor;
	array_index i;
	int error;

	if (max_serial + 1 < deltas->len)
		return pr_val_err("Deltas: Too many deltas (%zu) for serial %lu. (Negative serials not implemented.)",
		    deltas->len, max_serial);

	min_serial = max_serial + 1 - deltas->len;

	ARRAYLIST_FOREACH(deltas, cursor, i) {
		error = swap_until_sorted(deltas->array, i, min_serial,
		    max_serial);
		if (error)
			return error;
	}

	return 0;
}

struct update_notification *
update_notification_create(char const *uri)
{
	struct update_notification *result;

	result = pmalloc(sizeof(struct update_notification));

	global_data_init(&result->global_data);
	doc_data_init(&result->snapshot);
	deltas_head_init(&result->deltas_list);
	result->uri = pstrdup(uri);

	return result;
}

static void
delta_head_destroy(struct delta_head *delta)
{
	doc_data_cleanup(&delta->doc_data);
}

void
update_notification_destroy(struct update_notification *file)
{
	doc_data_cleanup(&file->snapshot);
	global_data_cleanup(&file->global_data);
	deltas_head_cleanup(&file->deltas_list, delta_head_destroy);
	free(file->uri);
	free(file);
}

struct snapshot *
snapshot_create(void)
{
	struct snapshot *tmp;

	tmp = pmalloc(sizeof(struct snapshot));
	global_data_init(&tmp->global_data);

	return tmp;
}

void
snapshot_destroy(struct snapshot *file)
{
	global_data_cleanup(&file->global_data);
	free(file);
}

struct delta *
delta_create(void)
{
	struct delta *tmp;

	tmp = pmalloc(sizeof(struct delta));
	global_data_init(&tmp->global_data);

	return tmp;
}

void
delta_destroy(struct delta *file)
{
	global_data_cleanup(&file->global_data);
	free(file);
}

struct publish *
publish_create(void)
{
	struct publish *tmp;

	tmp = pmalloc(sizeof(struct publish));
	doc_data_init(&tmp->doc_data);
	tmp->content = NULL;
	tmp->content_len = 0;

	return tmp;
}

void
publish_destroy(struct publish *file)
{
	doc_data_cleanup(&file->doc_data);
	free(file->content);
	free(file);
}

struct withdraw *
withdraw_create(void)
{
	struct withdraw *tmp;

	tmp = pmalloc(sizeof(struct withdraw));
	doc_data_init(&tmp->doc_data);

	return tmp;
}

void
withdraw_destroy(struct withdraw *file)
{
	doc_data_cleanup(&file->doc_data);
	free(file);
}
