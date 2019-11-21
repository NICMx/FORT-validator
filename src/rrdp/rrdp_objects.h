#ifndef SRC_RRDP_RRDP_OBJECTS_H_
#define SRC_RRDP_RRDP_OBJECTS_H_

#include <libxml/tree.h>
#include <sys/queue.h>
#include <stddef.h>

/* Common structures */
struct xml_source;

struct global_data {
	char *session_id;
	unsigned long serial;
};

struct doc_data {
	char *uri;
	unsigned char *hash;
	size_t hash_len;
};

struct publish {
	struct doc_data doc_data;
	unsigned char *content;
	SLIST_ENTRY(publish) next;
};

struct withdraw {
	struct doc_data doc_data;
	SLIST_ENTRY(withdraw) next;
};

/* Delta file structs */
SLIST_HEAD(publish_list, publish);
SLIST_HEAD(withdrawn_list, withdraw);

struct delta {
	struct global_data global_data;
	struct publish_list publish_list;
	struct withdrawn_list withdraw_list;
	struct xml_source *source;
};

/* Snapshot file structs */
struct snapshot {
	struct global_data global_data;
	struct publish_list publish_list;
	struct xml_source *source;
};

/* Update notification file structs */
struct delta_head {
	unsigned long serial;
	struct doc_data doc_data;
	SLIST_ENTRY(delta_head) next;
};

SLIST_HEAD(deltas_head, delta_head);

struct update_notification {
	struct global_data gdata;
	struct doc_data snapshot;
	struct deltas_head deltas_list;
};

int global_data_init(struct global_data *);
void global_data_cleanup(struct global_data *);

int doc_data_init(struct doc_data *);
void doc_data_cleanup(struct doc_data *);

int xml_source_create(struct xml_source **);
void xml_source_destroy(struct xml_source *);
int xml_source_set(struct xml_source *, xmlDoc *);

int update_notification_create(struct update_notification **);
void update_notification_destroy(struct update_notification *);

int update_notification_deltas_add(struct deltas_head *, unsigned long, char **,
    unsigned char **, size_t);

#endif /* SRC_RRDP_RRDP_OBJECTS_H_ */
