#ifndef SRC_RRDP_RRDP_OBJECTS_H_
#define SRC_RRDP_RRDP_OBJECTS_H_

#include <stddef.h>
#include <stdbool.h>
#include "data_structure/array_list.h"

/* Global RRDP files data */
struct notification_metadata {
	char *session_id;
	unsigned long serial;
};

/* Specific RRDP files data, in some cases the hash can be omitted */
struct file_metadata {
	char *uri;
	unsigned char *hash;
	size_t hash_len;
};

/* Represents a <publish> element */
struct publish {
	struct file_metadata meta;
	unsigned char *content;
	size_t content_len;
};

/* Represents a <withdraw> element */
struct withdraw {
	struct file_metadata meta;
};

/*
 * Delta file content.
 * Publish/withdraw list aren't remember, they are processed ASAP.
 */
struct delta {
	struct notification_metadata meta;
};

/*
 * Snapshot file content
 * Publish list isn't remember, is processed ASAP.
 */
struct snapshot {
	struct notification_metadata meta;
};

/* Delta element located at an update notification file */
struct delta_head {
	/*
	 * TODO this is not an RFC 1982 serial. It's supposed to be unbounded,
	 * so we should probably handle it as a string.
	 */
	unsigned long serial;
	struct file_metadata meta;
};

/* List of deltas inside an update notification file */
DEFINE_ARRAY_LIST_STRUCT(deltas_head, struct delta_head);
DECLARE_ARRAY_LIST_FUNCTIONS(deltas_head, struct delta_head)

/* Update notification file content and location URI */
struct update_notification {
	struct notification_metadata meta;
	struct file_metadata snapshot;
	struct deltas_head deltas_list;
	struct rpki_uri *uri;
};

void notification_metadata_init(struct notification_metadata *);
void notification_metadata_cleanup(struct notification_metadata *);

void metadata_init(struct file_metadata *);
void metadata_cleanup(struct file_metadata *);

void update_notification_init(struct update_notification *, struct rpki_uri *);
void update_notification_destroy(struct update_notification *);

typedef int (*delta_head_cb)(struct delta_head *, void *);
int deltas_head_for_each(struct deltas_head *, unsigned long, unsigned long,
    delta_head_cb, void *);
int deltas_head_sort(struct deltas_head *, unsigned long);

struct snapshot *snapshot_create(void);
void snapshot_destroy(struct snapshot *);

struct delta *delta_create(void);
void delta_destroy(struct delta *);

struct publish *publish_create(void);
void publish_destroy(struct publish *);

struct withdraw *withdraw_create(void);
void withdraw_destroy(struct withdraw *);

#endif /* SRC_RRDP_RRDP_OBJECTS_H_ */
