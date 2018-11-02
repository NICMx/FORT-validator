#ifndef TAL_H_
#define TAL_H_

/* This is RFC 7730. */

struct tal;

int tal_load(const char *, struct tal **);
void tal_destroy(struct tal *);

typedef int (*foreach_uri_cb)(char const *);
int foreach_uri(struct tal *, foreach_uri_cb);

#endif /* TAL_H_ */
