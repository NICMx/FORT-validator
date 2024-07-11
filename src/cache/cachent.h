#ifndef SRC_CACHE_CACHENT_H_
#define SRC_CACHE_CACHENT_H_

/* CACHE ENTity, CACHE elemENT, CACHE componENT */

#include <stdbool.h>
#include "data_structure/uthash.h"

/* XXX rename "touched" and "validated" into "preserve"? */

// XXX trees now separated; consider removing this flag
#define CNF_RSYNC		(1 << 0)
/*
 * Do we have a (full) copy in the cache?
 * If disabled, we don't know (because an ancestor was recursively rsync'd).
 */
#define CNF_CACHED		(1 << 1)
/*
 * Was it (allegedly) downloaded during the current cycle?
 * "Allegedly" because we might have rsync'd an ancestor.
 */
#define CNF_FRESH		(1 << 2)
/*
 * Did it change between the previous cycle and the current one?
 * (This is HTTP and RRDP only; rsync doesn't tell us.)
 */
#define CNF_CHANGED		(1 << 3)
/* Was it read during the current cycle? */
#define CNF_TOUCHED		(1 << 4)
/*
 * Did it validate successfully (at least once) during the current cycle?
 * (It's technically possible for two different repositories to map to the same
 * cache node. One of them is likely going to fail validation.)
 */
#define CNF_VALID		(1 << 5)
/* Is the node an RRDP Update Notification? */
#define CNF_NOTIFICATION	(1 << 6)
/* Withdrawn by RRDP? */
#define CNF_WITHDRAWN		(1 << 7)

/*
 * Flags for children of downloaded rsync nodes that should be cleaned later.
 * (FRESH prevents redownload.)
 */
#define RSYNC_INHERIT		(CNF_RSYNC | CNF_FRESH)

// XXX rename to cache_entity or cachent
struct cache_node {
	char const *name;	/* Points to the last component of @url XXX redundant */
	char *url;
	int flags;

	int dlerr;		/* Result code of recent download attempt */
	time_t mtim;		/* Last successful download time, or zero */

	/*
	 * If flags & CNF_FRESH, path to the temporal directory where we
	 * downloaded the latest refresh.
	 * (See --compare-dest at rsync(1). RRDP is basically the same.)
	 * Otherwise undefined.
	 *
	 * XXX this is not always a directory; rename to "tmppath"
	 */
	char *tmpdir;

	/* Only if flags & CNF_NOTIFICATION */
//	struct cachefile_notification notif;

	struct cache_node *parent;	/* Tree parent */
	struct cache_node *children;	/* Tree children */

	UT_hash_handle hh;		/* Hash table hook */
};

struct cache_node *cachent_create_root(char const *);

int cachent_traverse(struct cache_node *,
    bool (*cb)(struct cache_node *, char const *));

struct cache_node *cachent_provide(struct cache_node *, char const *);
void cachent_delete(struct cache_node *);

/* Recursive; tests only. */
void cachent_print(struct cache_node *);

#endif /* SRC_CACHE_CACHENT_H_ */
