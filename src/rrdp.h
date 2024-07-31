#ifndef SRC_RRDP_H_
#define SRC_RRDP_H_

#include <jansson.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <sys/queue.h>

struct cache_node;

/* These are supposed to be unbounded */
struct rrdp_serial {
	BIGNUM *num;
	char *str; /* String version of @num. */
};

struct rrdp_session {
	char *session_id;
	struct rrdp_serial serial;
};

#define RRDP_HASH_LEN SHA256_DIGEST_LENGTH

struct rrdp_hash {
	unsigned char bytes[RRDP_HASH_LEN];
	STAILQ_ENTRY(rrdp_hash) hook;
};

/*
 * Subset of the notification that is relevant to the TAL's cachefile.
 */
struct cachefile_notification {
	struct rrdp_session session;
	struct cache_node *subtree;
	/*
	 * The 1st one contains the hash of the session.serial delta.
	 * The 2nd one contains the hash of the session.serial - 1 delta.
	 * The 3rd one contains the hash of the session.serial - 2 delta.
	 * And so on.
	 */
	STAILQ_HEAD(, rrdp_hash) delta_hashes;
};

int rrdp_update(struct cache_node *);

json_t *rrdp_notif2json(struct cachefile_notification *);
int rrdp_json2notif(json_t *, struct cachefile_notification **);

void rrdp_notif_free(struct cachefile_notification *);

#endif /* SRC_RRDP_H_ */
