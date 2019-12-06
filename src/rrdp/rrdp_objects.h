#ifndef SRC_RRDP_RRDP_OBJECTS_H_
#define SRC_RRDP_RRDP_OBJECTS_H_

#include <stddef.h>
#include <stdbool.h>

/* Possible results for an RRDP URI comparison */
typedef enum {
	/* The URI exists and has the same session ID and serial */
	RRDP_URI_EQUAL,

	/* The URI exists but has distinct serial */
	RRDP_URI_DIFF_SERIAL,

	/* The URI exists but has distinct session ID */
	RRDP_URI_DIFF_SESSION,

	/* The URI doesn't exists */
	RRDP_URI_NOTFOUND,
} rrdp_uri_cmp_result_t;

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

/* Represents a <publish> element */
struct publish {
	struct doc_data doc_data;
	unsigned char *content;
	size_t content_len;
};

/* Represents a <withdraw> element */
struct withdraw {
	struct doc_data doc_data;
};

/*
 * Delta file content.
 * Publish/withdraw list aren't remember, they are processed ASAP.
 */
struct delta {
	struct global_data global_data;
};

/*
 * Snapshot file content
 * Publish list isn't remember, is processed ASAP.
 */
struct snapshot {
	struct global_data global_data;
};

/* Delta element located at an update notification file */
struct delta_head {
	unsigned long serial;
	struct doc_data doc_data;
};

/* List of deltas inside an update notification file */
struct deltas_head;

/* Update notification file content */
struct update_notification {
	struct global_data global_data;
	struct doc_data snapshot;
	struct deltas_head *deltas_list;
};

void global_data_init(struct global_data *);
void global_data_cleanup(struct global_data *);

void doc_data_init(struct doc_data *);
void doc_data_cleanup(struct doc_data *);

int update_notification_create(struct update_notification **);
void update_notification_destroy(struct update_notification *);

typedef int (*delta_head_cb)(struct delta_head *, void *);
int deltas_head_for_each(struct deltas_head *, unsigned long, unsigned long,
    delta_head_cb, void *);
int deltas_head_add(struct deltas_head *, unsigned long, unsigned long, char *,
    unsigned char *, size_t);

int deltas_head_set_size(struct deltas_head *, size_t);
bool deltas_head_values_set(struct deltas_head *);

int snapshot_create(struct snapshot **);
void snapshot_destroy(struct snapshot *);

int delta_create(struct delta **);
void delta_destroy(struct delta *);

int publish_create(struct publish **);
void publish_destroy(struct publish *);

int withdraw_create(struct withdraw **);
void withdraw_destroy(struct withdraw *);

#endif /* SRC_RRDP_RRDP_OBJECTS_H_ */
