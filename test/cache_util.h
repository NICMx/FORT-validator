#ifndef TEST_CACHE_UTIL_H_
#define TEST_CACHE_UTIL_H_

#include <stdarg.h>

void ck_assert_cachent_eq(struct cache_node *, struct cache_node *);

struct cache_node *rftnode(char const *, char const *, int, char const *, ...);
struct cache_node *rfnode(char const *, char const *, int, ...);
struct cache_node *rnode(char const *, char const *, ...);

struct cache_node *hftnode(char const *, char const *, int, char const *, ...);
struct cache_node *hfnode(char const *, char const *, int, ...);
struct cache_node *hnode(char const *, char const *, ...);

/* rsync offset to url + path */
#define RO2UP(offset) "rsync://" offset, "tmp/rsync/" offset
/* https offset to url + path */
#define HO2UP(offset) "https://" offset, "tmp/https/" offset

/* rsync empty to url + path */
#define RE2UP "rsync://", "tmp/rsync"
/* https empty to url + path */
#define HE2UP "https://", "tmp/https"

#endif /* TEST_CACHE_UTIL_H_ */
