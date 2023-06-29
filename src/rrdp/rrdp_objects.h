#ifndef SRC_RRDP_RRDP_OBJECTS_H_
#define SRC_RRDP_RRDP_OBJECTS_H_

#include <stddef.h>
#include <stdbool.h>
#include "data_structure/array_list.h"

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
	/*
	 * TODO this is not an RFC 1982 serial. It's supposed to be unbounded,
	 * so we should probably handle it as a string.
	 */
	unsigned long serial;
	struct doc_data doc_data;
};

/* List of deltas inside an update notification file */
DEFINE_ARRAY_LIST_STRUCT(deltas_head, struct delta_head);
DECLARE_ARRAY_LIST_FUNCTIONS(deltas_head, struct delta_head)

/* Update notification file content and location URI */
struct update_notification {
	struct global_data global_data;
	struct doc_data snapshot;
	struct deltas_head deltas_list;
	char *uri;
};

void global_data_init(struct global_data *);
void global_data_cleanup(struct global_data *);

void doc_data_init(struct doc_data *);
void doc_data_cleanup(struct doc_data *);

struct update_notification *update_notification_create(char const *);
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
