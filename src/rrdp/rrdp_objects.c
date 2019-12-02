#include "rrdp_objects.h"

#include <sys/queue.h>
#include <string.h>
#include "log.h"

struct delta_head {
	unsigned long serial;
	struct doc_data doc_data;
	unsigned int references;
	SLIST_ENTRY(delta_head) next;
};

/* List of deltas inside an update notification file */
SLIST_HEAD(deltas_head, delta_head);

int
global_data_init(struct global_data *data)
{
	data->session_id = NULL;
	return 0;
}

void
global_data_cleanup(struct global_data *data)
{
	free(data->session_id);
}

int
doc_data_init(struct doc_data *data)
{
	data->hash = NULL;
	data->hash_len = 0;
	data->uri = NULL;
	return 0;
}

void
doc_data_cleanup(struct doc_data *data)
{
	free(data->hash);
	free(data->uri);
}

static int
delta_head_create(struct delta_head **result)
{
	struct delta_head *tmp;

	tmp = malloc(sizeof(struct delta_head));
	if (tmp == NULL)
		return pr_enomem();

	doc_data_init(&tmp->doc_data);
	tmp->references = 1;

	*result = tmp;
	return 0;
}

unsigned long
delta_head_get_serial(struct delta_head *delta_head)
{
	return delta_head->serial;
}

struct doc_data *
delta_head_get_doc_data(struct delta_head *delta_head)
{
	return &delta_head->doc_data;
}

void
delta_head_refget(struct delta_head *delta_head)
{
	delta_head->references++;
}

void
delta_head_refput(struct delta_head *delta_head)
{
	delta_head->references--;
	if (delta_head->references == 0) {
		doc_data_cleanup(&delta_head->doc_data);
		free(delta_head);
	}
}

static int
deltas_head_create(struct deltas_head **deltas)
{
	struct deltas_head *tmp;

	tmp = malloc(sizeof(struct deltas_head));
	if (tmp == NULL)
		return pr_enomem();

	SLIST_INIT(tmp);

	*deltas = tmp;
	return 0;
}

static void
deltas_head_destroy(struct deltas_head *deltas)
{
	struct delta_head *head;

	while (!SLIST_EMPTY(deltas)) {
		head = deltas->slh_first;
		SLIST_REMOVE_HEAD(deltas, next);
		delta_head_refput(head);
	}
	free(deltas);
}

int
update_notification_create(struct update_notification **file)
{
	struct update_notification *tmp;
	int error;

	tmp = malloc(sizeof(struct update_notification));
	if (tmp == NULL)
		return pr_enomem();

	error = deltas_head_create(&tmp->deltas_list);
	if (error) {
		free(tmp);
		return error;
	}

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
	free(file);
}

/* A new delta_head will be allocated, as well as its URI and HASH */
int
deltas_head_add(struct deltas_head *deltas, unsigned long serial,
    char *uri, unsigned char *hash, size_t hash_len)
{
	struct delta_head *elem;
	int error;

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

	SLIST_INSERT_HEAD(deltas, elem, next);

	return 0;
}

int
deltas_head_for_each(struct deltas_head *deltas, delta_head_cb cb, void *arg)
{
	struct delta_head *cursor;
	int error;

	SLIST_FOREACH(cursor, deltas, next) {
		error = cb(cursor, arg);
		if (error)
			return error;
	}

	return 0;
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
