#include "rrdp_objects.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"

/*
 * List of deltas inside an update notification file.
 *
 * The structure functions are extended and will have the following meaning:
 *   - capacity : is the size of the array, must be set before using the array
 *                and can't be modified.
 *   - len      : number of elements set in the array.
 *
 * This struct is a diff version of array_list, utilized to store only the
 * amount of deltas that may be needed and validate that an update notification
 * file has a contiguous set of deltas.
 */
struct deltas_head {
	/** Unidimensional array. Initialized lazily. */
	struct delta_head **array;
	/** Number of elements in @array. */
	size_t len;
	/** Actual allocated slots in @array. */
	size_t capacity;
};

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
	data->hash = NULL;
	data->hash_len = 0;
	data->uri = NULL;
}

void
doc_data_cleanup(struct doc_data *data)
{
	free(data->hash);
	free(data->uri);
}

int
delta_head_create(struct delta_head **result)
{
	struct delta_head *tmp;

	tmp = malloc(sizeof(struct delta_head));
	if (tmp == NULL)
		return pr_enomem();

	doc_data_init(&tmp->doc_data);

	*result = tmp;
	return 0;
}

void
delta_head_destroy(struct delta_head *delta_head)
{
	if (delta_head) {
		doc_data_cleanup(&delta_head->doc_data);
		free(delta_head);
	}
}

static void
deltas_head_init(struct deltas_head *list)
{
	list->array = NULL;
	list->len = 0;
	list->capacity = 0;
}

static void
deltas_head_cleanup(struct deltas_head *list)
{
	size_t i;

	for (i = 0; i < list->capacity; i++)
		delta_head_destroy(list->array[i]);
	if (list->array)
		free(list->array);
}

static int
deltas_head_create(struct deltas_head **deltas)
{
	struct deltas_head *tmp;

	tmp = malloc(sizeof(struct deltas_head));
	if (tmp == NULL)
		return pr_enomem();

	deltas_head_init(tmp);

	*deltas = tmp;
	return 0;
}

static void
deltas_head_destroy(struct deltas_head *deltas)
{
	deltas_head_cleanup(deltas);
	free(deltas);
}

int
deltas_head_set_size(struct deltas_head *deltas, size_t capacity)
{
	size_t i;

	if (deltas->array != NULL)
		pr_crit("Size of this list can't be modified");

	deltas->capacity = capacity;
	if (capacity == 0)
		return 0; /* Ok, list can have 0 elements */

	deltas->array = malloc(deltas->capacity
	    * sizeof(struct delta_head *));
	if (deltas->array == NULL)
		return pr_enomem();

	/* Point all elements to NULL */
	for (i = 0; i < deltas->capacity; i++)
		deltas->array[i] = NULL;

	return 0;
}

/*
 * A new delta_head will be allocated at its corresponding position inside
 * @deltas (also its URI and HASH will be allocated). The position is calculated
 * using the difference between @max_serial and @serial.
 *
 * The following errors can be returned due to a wrong @position:
 *   -EEXIST: There's already an element at @position.
 *   -EINVAL: @position can't be inside @deltas list, meaning that such element
 *            isn't part of a contiguous list.
 *
 * Don't forget to call deltas_head_set_size() before this!!
 */
int
deltas_head_add(struct deltas_head *deltas, unsigned long max_serial,
    unsigned long serial, char *uri, unsigned char *hash, size_t hash_len)
{
	struct delta_head *elem;
	size_t position;
	int error;

	position = deltas->capacity - 1 - (max_serial - serial);
	if (position < 0 || position > deltas->capacity - 1)
		return -EINVAL;

	if (deltas->array[position] != NULL)
		return -EEXIST;

	elem = NULL;
	error = delta_head_create(&elem);
	if (error)
		return error;

	elem->serial = serial;

	elem->doc_data.uri = strdup(uri);
	if (elem->doc_data.uri == NULL) {
		free(elem);
		return pr_enomem();
	}

	elem->doc_data.hash_len = hash_len;
	elem->doc_data.hash = malloc(hash_len);
	if (elem->doc_data.hash == NULL) {
		free(elem->doc_data.uri);
		free(elem);
		return pr_enomem();
	}
	memcpy(elem->doc_data.hash, hash, hash_len);

	deltas->array[position] = elem;
	deltas->len++;

	return 0;
}

/* Are all expected values set? */
bool
deltas_head_values_set(struct deltas_head *deltas)
{
	return deltas->len == deltas->capacity;
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
	if (deltas->capacity == 0) {
		pr_warn("There's no delta list to process.");
		return -ENOENT;
	}

	pr_debug("Getting RRDP deltas from serial %lu to %lu.", from_serial,
	    max_serial);
	from = deltas->capacity - (max_serial - from_serial);
	for (index = from; index < deltas->capacity; index++) {
		error = cb(deltas->array[index], arg);
		if (error)
			return error;
	}

	return 0;
}

int
update_notification_create(struct update_notification **file)
{
	struct update_notification *tmp;
	struct deltas_head *list;
	int error;

	tmp = malloc(sizeof(struct update_notification));
	if (tmp == NULL)
		return pr_enomem();

	list = NULL;
	error = deltas_head_create(&list);
	if (error) {
		free(tmp);
		return pr_enomem();
	}
	tmp->deltas_list = list;
	tmp->uri = NULL;

	global_data_init(&tmp->global_data);
	doc_data_init(&tmp->snapshot);

	*file = tmp;
	return 0;
}

void
update_notification_destroy(struct update_notification *file)
{
	doc_data_cleanup(&file->snapshot);
	global_data_cleanup(&file->global_data);
	deltas_head_destroy(file->deltas_list);
	free(file->uri);
	free(file);
}

int
snapshot_create(struct snapshot **file)
{
	struct snapshot *tmp;

	tmp = malloc(sizeof(struct snapshot));
	if (tmp == NULL)
		return pr_enomem();

	global_data_init(&tmp->global_data);

	*file = tmp;
	return 0;
}

void
snapshot_destroy(struct snapshot *file)
{
	global_data_cleanup(&file->global_data);
	free(file);
}

int
delta_create(struct delta **file)
{
	struct delta *tmp;

	tmp = malloc(sizeof(struct delta));
	if (tmp == NULL)
		return pr_enomem();

	global_data_init(&tmp->global_data);

	*file = tmp;
	return 0;
}

void
delta_destroy(struct delta *file)
{
	global_data_cleanup(&file->global_data);
	free(file);
}

int
publish_create(struct publish **file)
{
	struct publish *tmp;

	tmp = malloc(sizeof(struct publish));
	if (tmp == NULL)
		return pr_enomem();

	doc_data_init(&tmp->doc_data);
	tmp->content = NULL;
	tmp->content_len = 0;

	*file = tmp;
	return 0;
}

void
publish_destroy(struct publish *file)
{
	doc_data_cleanup(&file->doc_data);
	free(file->content);
	free(file);
}

int
withdraw_create(struct withdraw **file)
{
	struct withdraw *tmp;

	tmp = malloc(sizeof(struct withdraw));
	if (tmp == NULL)
		return pr_enomem();

	doc_data_init(&tmp->doc_data);

	*file = tmp;
	return 0;
}

void
withdraw_destroy(struct withdraw *file)
{
	doc_data_cleanup(&file->doc_data);
	free(file);
}
