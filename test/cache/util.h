#ifndef TEST_CACHE_UTIL_H_
#define TEST_CACHE_UTIL_H_

#include <stdarg.h>
#include "cache/cachent.h"

struct cache_node *vnode(char const *, int, char const *, va_list);
struct cache_node *uftnode(char const *, int , char const *, ...);
struct cache_node *ufnode(char const *, int , ...);
struct cache_node *unode(char const *, ...);

#endif /* TEST_CACHE_UTIL_H_ */
