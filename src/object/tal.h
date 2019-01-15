#ifndef TAL_OBJECT_H_
#define TAL_OBJECT_H_

/* This is RFC 7730. */

#include <stddef.h>

struct tal;

int tal_load(const char *, struct tal **);
void tal_destroy(struct tal *);

typedef int (*foreach_uri_cb)(struct tal *, char const *);
int foreach_uri(struct tal *, foreach_uri_cb);
void tal_shuffle_uris(struct tal *);

void tal_get_spki(struct tal *, unsigned char const **, size_t *);

#endif /* TAL_OBJECT_H_ */
