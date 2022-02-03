#ifndef SRC_RRDP_TYPES_H_
#define SRC_RRDP_TYPES_H_

#include <libxml/xmlreader.h>
#include "types/uri.h"
#include "data_structure/array_list.h"

struct rrdp_session {
	char *id;
	unsigned long serial;
};

/* An RRDP file, described by the Update Notification file. */
struct rrdp_file_metadata {
	struct rpki_uri *uri;
	unsigned char *hash; /* Can be omitted sometimes. */
	size_t hash_len;
};

void rrdp_file_metadata_init(struct rrdp_file_metadata *);
void rrdp_file_metadata_cleanup(struct rrdp_file_metadata *);
int rrdp_file_metadata_validate_hash(struct rrdp_file_metadata *);

/* Parsed delta element, from the Update Notification file. */
struct rrdp_notification_delta {
	/*
	 * TODO this is not an RFC 1982 serial. It's supposed to be unbounded,
	 * so we should probably handle it as a string.
	 */
	unsigned long serial;
	struct rrdp_file_metadata meta;
};

DEFINE_ARRAY_LIST_STRUCT(rrdp_notification_deltas,
    struct rrdp_notification_delta);
DECLARE_ARRAY_LIST_FUNCTIONS(rrdp_notification_deltas,
    struct rrdp_notification_delta)

/* Update notification file content and location URI */
struct rrdp_notification {
	struct rpki_uri *uri;
	struct rrdp_session session;
	struct rrdp_file_metadata snapshot;
	struct rrdp_notification_deltas deltas_list;
};

void rrdp_notification_init(struct rrdp_notification *, struct rpki_uri *);
void rrdp_notification_cleanup(struct rrdp_notification *);

int parse_simple_uri_attribute(xmlTextReaderPtr, struct rrdp_file_metadata *);
int parse_caged_uri_attribute(xmlTextReaderPtr, struct rrdp_notification *,
    struct rrdp_file_metadata *);
int parse_hash_attribute(xmlTextReaderPtr, bool, struct rrdp_file_metadata *);

int parse_header_tag(xmlTextReaderPtr, struct rrdp_session *);
int validate_header_tag(xmlTextReaderPtr, struct rrdp_session *);
int handle_publish_tag(xmlTextReaderPtr, struct rrdp_notification *, bool);

#endif /* SRC_RRDP_TYPES_H_ */
