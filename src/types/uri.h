#ifndef SRC_TYPES_URI_H_
#define SRC_TYPES_URI_H_

#include <stdbool.h>
#include <stddef.h>

#include "types/arraylist.h"

#define RPKI_SCHEMA_LEN 8 /* strlen("rsync://"), strlen("https://") */

struct uri {
	char *_str;
	size_t _len;
};

int uri_init(struct uri *, char const *);
void __uri_init(struct uri *, char const *, size_t);
#define __URI_INIT(uri, str) __uri_init(uri, str, strlen(str))
void uri_copy(struct uri *, struct uri const *);
void uri_cleanup(struct uri *);

#define uri_str(u) ((char const *)((u)->_str))
#define uri_len(u) ((size_t const)((u)->_len))

bool uri_is_rsync(struct uri const *);
bool uri_is_https(struct uri const *);

bool uri_equals(struct uri const *, struct uri const *);
bool uri_has_extension(struct uri const *, char const *);
bool uri_same_origin(struct uri const *, struct uri const *);

int uri_parent(struct uri const *, struct uri *);
void uri_child(struct uri const *, char const *, size_t, struct uri *);
#define URI_CHILD(uri, name, child) uri_child(uri, name, strlen(name), child)

/* Plural */

DEFINE_ARRAY_LIST_STRUCT(uris, struct uri);
DECLARE_ARRAY_LIST_FUNCTIONS(uris, struct uri)

#endif /* SRC_TYPES_URI_H_ */
