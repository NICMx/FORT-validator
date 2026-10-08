#ifndef SRC_RRDP_XML_H_
#define SRC_RRDP_XML_H_

#include <openssl/bn.h>
#include <time.h>

#include "cachefile.h"
#include "file.h"
#include "hash.h"
#include "types/uri.h"

BIGNUM *BN_create(void);

struct rrdp_serial {
	BIGNUM *num;
	char *str;			/* String version of @num. */
};

void serial_copy(struct rrdp_serial *, struct rrdp_serial *);
bool serial_equals(struct rrdp_serial *, struct rrdp_serial *);
int str2serial(char const *, struct rrdp_serial *);
void serial_cleanup(struct rrdp_serial *);

struct rrdp_id {
	char *session_id;
	struct rrdp_serial serial;
};

struct file_metadata {
	struct uri uri;
	struct rrdp_hash hash;
};

/* A delta tag, listed by a notification */
/* (Not the actual delta file) */
struct notification_delta {
	struct rrdp_serial serial;
	struct file_metadata meta;
};

struct notification_deltas {
	struct notification_delta *arr;
	size_t len;
	size_t cap;
};

/* A deserialized "Update Notification" file (aka "Notification"). */
struct update_notification {
	struct rrdp_id session;
	struct file_metadata snapshot;
	struct notification_deltas deltas;
	struct uri const *url;
};

void notification_cleanup(struct update_notification *);

int rrdpxml_fetch_notif(struct uri const *, time_t, bool *,
    struct update_notification *);
int rrdpxml_explode_snapshot(struct update_notification const *,
    struct files_ht *, struct cache_sequence *);
int rrdpxml_explode_delta(struct update_notification *,
    struct notification_delta *,
    struct files_ht *, struct cache_sequence *);

#endif /* SRC_RRDP_XML_H_ */
