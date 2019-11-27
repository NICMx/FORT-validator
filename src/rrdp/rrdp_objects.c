#include "rrdp_objects.h"

#include "log.h"

struct xml_source {
	xmlDoc *doc;
};

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

int
xml_source_create(struct xml_source **src)
{
	struct xml_source *tmp;

	tmp = malloc(sizeof(struct xml_source));
	if (tmp == NULL)
		return pr_enomem();

	*src = tmp;
	return 0;
}

void
xml_source_destroy(struct xml_source *src){
	if (src != NULL) {
		xmlFreeDoc(src->doc);
		free(src);
	}
}

int
xml_source_set(struct xml_source *src, xmlDoc *orig)
{
	xmlDoc *cpy;

	cpy = xmlCopyDoc(orig, 1);
	if (cpy == NULL)
		return pr_enomem();

	src->doc = cpy;
	return 0;
}

int
update_notification_create(struct update_notification **file)
{
	struct update_notification *tmp;

	tmp = malloc(sizeof(struct update_notification));
	if (tmp == NULL)
		return pr_enomem();

	global_data_init(&tmp->global_data);
	doc_data_init(&tmp->snapshot);

	SLIST_INIT(&tmp->deltas_list);

	*file = tmp;
	return 0;
}

void
update_notification_destroy(struct update_notification *file)
{
	struct deltas_head *list;
	struct delta_head *head;

	list = &file->deltas_list;
	while (!SLIST_EMPTY(list)) {
		head = list->slh_first;
		SLIST_REMOVE_HEAD(list, next);
		doc_data_cleanup(&head->doc_data);
		free(head);
	}
	doc_data_cleanup(&file->snapshot);
	global_data_cleanup(&file->global_data);

	free(file);
}

/* URI and HASH must already be allocated */
int
update_notification_deltas_add(struct deltas_head *deltas, unsigned long serial,
    char **uri, unsigned char **hash, size_t hash_len)
{
	struct delta_head *elem;

	elem = malloc(sizeof(struct delta_head));
	if (elem == NULL)
		return pr_enomem();

	elem->serial = serial;
	elem->doc_data.uri = *uri;
	elem->doc_data.hash = *hash;
	elem->doc_data.hash_len = hash_len;
	SLIST_INSERT_HEAD(deltas, elem, next);

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
	SLIST_INIT(&tmp->publish_list);
	tmp->source = NULL;

	*file = tmp;
	return 0;
}

void
snapshot_destroy(struct snapshot *file)
{
	struct publish_list *list;
	struct publish *head;

	list = &file->publish_list;
	while (!SLIST_EMPTY(list)) {
		head = list->slh_first;
		SLIST_REMOVE_HEAD(list, next);
		doc_data_cleanup(&head->doc_data);
		free(head->content);
		free(head);
	}
	global_data_cleanup(&file->global_data);
	xml_source_destroy(file->source);

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
publish_list_add(struct publish_list *list, struct publish *elem)
{
	SLIST_INSERT_HEAD(list, elem, next);
	return 0;
}
