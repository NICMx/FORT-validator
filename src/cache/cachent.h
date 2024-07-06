#ifndef SRC_CACHE_CACHENT_H_
#define SRC_CACHE_CACHENT_H_

/* CACHE ENTity, CACHE elemENT, CACHE componENT */

#include "data_structure/uthash.h"

#define RPKI_SCHEMA_LEN 8 /* strlen("rsync://"), strlen("https://") */

/* XXX rename "touched" and "validated" into "preserve"? */

#define CNF_RSYNC		(1 << 0)
/* Do we have a copy in the cache? */
#define CNF_CACHED		(1 << 1)
/* Was it downloaded during the current cycle? XXX Probably rename to "FRESH" */
#define CNF_DOWNLOADED		(1 << 2)
/* Did it change between the previous cycle and the current one? */
#define CNF_CHANGED		(1 << 3)
/* Was it read during the current cycle? */
#define CNF_TOUCHED		(1 << 4)
/*
 * Did it validate successfully (at least once) during the current cycle?
 * (It's technically possible for two different repositories to map to the same
 * cache node. One of them is likely going to fail validation.)
 */
#define CNF_VALIDATED		(1 << 5)
/* Is the node an RRDP Update Notification? */
#define CNF_NOTIFICATION	(1 << 6)
/* Withdrawn by RRDP? */
#define CNF_WITHDRAWN		(1 << 7)

// XXX rename to cache_entity or cachent
struct cache_node {
	char const *name; /* Points to the last component of @url */
	char *url;
	int flags;
	/* Last successful download time, or zero */
	time_t mtim;
	/*
	 * If flags & CNF_DOWNLOADED, path to the temporal directory where we
	 * downloaded the latest refresh.
	 * (See --compare-dest at rsync(1). RRDP is basically the same.)
	 * Otherwise undefined.
	 *
	 * XXX this is not always a directory; rename to "tmppath"
	 */
	char *tmpdir;

	/* Only if flags & CNF_NOTIFICATION. */
//	struct cachefile_notification notif;

	/* Tree parent. Only defined during cleanup. */
	struct cache_node *parent;
	/* Tree children. */
	struct cache_node *children;

	UT_hash_handle hh; /* Hash table hook */
};

int cachent_traverse(struct cache_node *,
    bool (*cb)(struct cache_node *, char const *));

struct cache_node *cachent_provide(struct cache_node *, char const *);
void cachent_delete(struct cache_node *);

/* Recursive; tests only. */
void cachent_print(struct cache_node *);

#endif /* SRC_CACHE_CACHENT_H_ */
