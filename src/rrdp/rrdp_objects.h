#ifndef SRC_RRDP_RRDP_OBJECTS_H_
#define SRC_RRDP_RRDP_OBJECTS_H_

#include <libxml/tree.h>
#include <sys/queue.h>
#include <stddef.h>

/* Possible results for an RRDP URI comparison */
enum rrdp_uri_cmp_result {
	/* The URI doesn't exists */
	RRDP_URI_NOTFOUND,

	/* The URI exists and has the same session ID and serial */
	RRDP_URI_EQUAL,

	/* The URI exists but has distinct serial */
	RRDP_URI_DIFF_SERIAL,

	/* The URI exists but has distinct session ID */
	RRDP_URI_DIFF_SESSION,
};

/* Structure to remember the XML source file (useful for hash validations) */
struct xml_source;

/* Global RRDP files data */
struct global_data {
	char *session_id;
	unsigned long serial;
};

/* Specific RRDP files data, in some cases the hash can be omitted */
struct doc_data {
	char *uri;
	unsigned char *hash;
	size_t hash_len;
};

/* Represents a <publish> element to be utilized inside a list */
struct publish {
	struct doc_data doc_data;
	unsigned char *content;
	size_t content_len;
	SLIST_ENTRY(publish) next;
};

/* Represents a <withdraw> element to be utilized inside a list */
struct withdraw {
	struct doc_data doc_data;
	SLIST_ENTRY(withdraw) next;
};

/* List of <publish> elements (either in a delta or a snapshot file) */
SLIST_HEAD(publish_list, publish);
/* List of <withdraw> elements */
SLIST_HEAD(withdrawn_list, withdraw);

/* Delta file content */
struct delta {
	struct global_data global_data;
	struct publish_list publish_list;
	struct withdrawn_list withdraw_list;
	struct xml_source *source;
};

/* Snapshot file content */
struct snapshot {
	struct global_data global_data;
	struct publish_list publish_list;
	struct xml_source *source;
};

/* Delta element located at an update notification file */
struct delta_head {
	unsigned long serial;
	struct doc_data doc_data;
	SLIST_ENTRY(delta_head) next;
};

/* List of deltas inside an update notification file */
SLIST_HEAD(deltas_head, delta_head);

struct update_notification {
	struct global_data global_data;
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

int snapshot_create(struct snapshot **);
void snapshot_destroy(struct snapshot *);

int publish_create(struct publish **);
void publish_destroy(struct publish *);

int publish_list_add(struct publish_list *, struct publish *);


#endif /* SRC_RRDP_RRDP_OBJECTS_H_ */
