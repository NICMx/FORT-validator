#ifndef TEST_CACHE_UTIL_H_
#define TEST_CACHE_UTIL_H_

#include <stdarg.h>
#include "cachent.h"

struct cache_node *ruftnode(char const *, int , char const *, ...);
struct cache_node *rufnode(char const *, int , ...);
struct cache_node *runode(char const *, ...);

struct cache_node *huftnode(char const *, int , char const *, ...);
struct cache_node *hufnode(char const *, int , ...);
struct cache_node *hunode(char const *, ...);

#endif /* TEST_CACHE_UTIL_H_ */
