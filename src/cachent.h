#ifndef SRC_CACHE_CACHENT_H_
#define SRC_CACHE_CACHENT_H_

/* CACHE ENTity, CACHE elemENT, CACHE componENT */

#include <stdbool.h>
#include <sys/stat.h>

#include "rrdp.h"
#include "types/uthash.h"

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
/* Was it read during the current cycle? */
#define CNF_TOUCHED		(1 << 4)
/*
 * Did it validate successfully (at least once) during the current cycle?
 * (It's technically possible for two different repositories to map to the same
 * cache node. One of them is likely going to fail validation.)
 * This only refers to the tmp path; The final path, if it exists, always
 * contains valid objects (until expiration).
 */
#define CNF_VALID		(1 << 5)
/* Is the node an RRDP Update Notification? */
#define CNF_NOTIFICATION	(1 << 6)
/* Withdrawn by RRDP? */
#define CNF_WITHDRAWN		(1 << 7)

#define CNF_FREE_URL		(1 << 8)
#define CNF_FREE_PATH		(1 << 9)
#define CNF_FREE_TMPPATH	(1 << 10)

/*
 * Flags for children of downloaded rsync nodes that should be cleaned later.
 * (FRESH prevents redownload.)
 * XXX useful?
 */
#define RSYNC_INHERIT		(CNF_RSYNC | CNF_FRESH)

struct cache_node {
	char *url;		/* rsync://a.b.c/d/e (normalized) */
	char *path;		/* path/to/cache/rsync/a.b.c/d/e */
	char const *name;	/* Points to the last component of @url or @path XXX redundant */
	int flags;		/* CNF_* */

	int dlerr;		/* Result code of recent download attempt */
	time_t mtim;		/* Last successful download time, or zero */

	/*
	 * If download attempted, path to the temporal directory where the
	 * refresh was dumped.
	 * (See --compare-dest at rsync(1). RRDP is basically the same.)
	 * Otherwise NULL.
	 */
	char *tmppath;		/* path/to/cache/tmp/1234 */

	/* Only if flags & CNF_NOTIFICATION */
	struct cachefile_notification rrdp;

	struct cache_node *parent;	/* Tree parent */
	struct cache_node *children;	/* Tree children */

	UT_hash_handle hh;		/* Hash table hook */
};

struct cache_node *cachent_root_rsync(void);
struct cache_node *cachent_root_https(void);

void cachent_traverse(struct cache_node *, bool (*cb)(struct cache_node *));

struct cache_node *cachent_find(struct cache_node *, char const *,
    struct cache_node **);
struct cache_node *cachent_provide(struct cache_node *, char const *);
int cachent_delete(struct cache_node *);

/* Recursive; tests only. */
void cachent_print(struct cache_node *);

#endif /* SRC_CACHE_CACHENT_H_ */
