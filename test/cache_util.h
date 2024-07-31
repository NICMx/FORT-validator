#ifndef TEST_CACHE_UTIL_H_
#define TEST_CACHE_UTIL_H_

#include <stdarg.h>
#include "cachent.h"

void ck_assert_cachent_eq(struct cache_node *, struct cache_node *);

struct cache_node *vcreate_node(char const *, char const *, int, char const *, va_list);

// XXX Rename ?
struct cache_node *ruftnode(char const *, char const *, int, char const *, ...);
struct cache_node *rufnode(char const *, char const *, int, ...);
struct cache_node *runode(char const *, char const *, ...);

struct cache_node *huftnode(char const *, char const *, int, char const *, ...);
struct cache_node *hufnode(char const *, char const *, int, ...);
struct cache_node *hunode(char const *, char const *, ...);

/* rsync offset to url + path */
#define RO2UP(offset) "rsync://" offset, "tmp/rsync/" offset
/* https offset to url + path */
#define HO2UP(offset) "https://" offset, "tmp/https/" offset

/* rsync empty to url + path */
#define RE2UP "rsync://", "tmp/rsync"
/* https empty to url + path */
#define HE2UP "https://", "tmp/https"

#endif /* TEST_CACHE_UTIL_H_ */
