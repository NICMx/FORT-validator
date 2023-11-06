#ifndef SRC_RRDP_RRDP_OBJECTS_H_
#define SRC_RRDP_RRDP_OBJECTS_H_

#include "data_structure/array_list.h"

/* Global RRDP files data */
struct notification_metadata {
	char *session_id;
	unsigned long serial;
};

/* Specific RRDP files data, in some cases the hash can be omitted */
struct file_metadata {
	struct rpki_uri *uri;
	unsigned char *hash;
	size_t hash_len;
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
void update_notification_cleanup(struct update_notification *);

typedef int (*delta_head_cb)(struct delta_head *, void *);
int deltas_head_for_each(struct deltas_head *, unsigned long, unsigned long,
    delta_head_cb, void *);
int deltas_head_sort(struct deltas_head *, unsigned long);

#endif /* SRC_RRDP_RRDP_OBJECTS_H_ */
