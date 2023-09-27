#include "rrdp/rrdp_objects.h"

#include <errno.h>
#include "alloc.h"
#include "log.h"
#include "types/uri.h"

DEFINE_ARRAY_LIST_FUNCTIONS(deltas_head, struct delta_head, )

void
notification_metadata_init(struct notification_metadata *meta)
{
	meta->session_id = NULL;
}

void
notification_metadata_cleanup(struct notification_metadata *meta)
{
	free(meta->session_id);
}

void
metadata_init(struct file_metadata *meta)
{
	meta->uri = NULL;
	meta->hash = NULL;
	meta->hash_len = 0;
}

void
metadata_cleanup(struct file_metadata *meta)
{
	free(meta->hash);
	free(meta->uri);
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
	array_index i;
	int error;

	if (max_serial + 1 < deltas->len)
		return pr_val_err("Deltas: Too many deltas (%zu) for serial %lu. (Negative serials not implemented.)",
		    deltas->len, max_serial);

	min_serial = max_serial + 1 - deltas->len;

	ARRAYLIST_FOREACH_IDX(deltas, i) {
		error = swap_until_sorted(deltas->array, i, min_serial,
		    max_serial);
		if (error)
			return error;
	}

	return 0;
}

void
update_notification_init(struct update_notification *notification,
    struct rpki_uri *uri)
{
	notification_metadata_init(&notification->meta);
	metadata_init(&notification->snapshot);
	deltas_head_init(&notification->deltas_list);
	notification->uri = uri_refget(uri);
}

static void
delta_head_destroy(struct delta_head *delta)
{
	metadata_cleanup(&delta->meta);
}

void
update_notification_destroy(struct update_notification *file)
{
	metadata_cleanup(&file->snapshot);
	notification_metadata_cleanup(&file->meta);
	deltas_head_cleanup(&file->deltas_list, delta_head_destroy);
	uri_refput(file->uri);
}

struct snapshot *
snapshot_create(void)
{
	struct snapshot *tmp;

	tmp = pmalloc(sizeof(struct snapshot));
	notification_metadata_init(&tmp->meta);

	return tmp;
}

void
snapshot_destroy(struct snapshot *file)
{
	notification_metadata_cleanup(&file->meta);
	free(file);
}

struct delta *
delta_create(void)
{
	struct delta *tmp;

	tmp = pmalloc(sizeof(struct delta));
	notification_metadata_init(&tmp->meta);

	return tmp;
}

void
delta_destroy(struct delta *file)
{
	notification_metadata_cleanup(&file->meta);
	free(file);
}

struct publish *
publish_create(void)
{
	struct publish *tmp;

	tmp = pmalloc(sizeof(struct publish));
	metadata_init(&tmp->meta);
	tmp->content = NULL;
	tmp->content_len = 0;

	return tmp;
}

void
publish_destroy(struct publish *file)
{
	metadata_cleanup(&file->meta);
	free(file->content);
	free(file);
}

struct withdraw *
withdraw_create(void)
{
	struct withdraw *tmp;

	tmp = pmalloc(sizeof(struct withdraw));
	metadata_init(&tmp->meta);

	return tmp;
}

void
withdraw_destroy(struct withdraw *file)
{
	metadata_cleanup(&file->meta);
	free(file);
}
