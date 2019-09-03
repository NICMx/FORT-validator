#ifndef TAL_OBJECT_H_
#define TAL_OBJECT_H_

/* This is RFC 7730. */

#include <stddef.h>
#include "uri.h"
#include "rtr/db/db_table.h"

struct tal;

int tal_load(char const *, struct tal **);
void tal_destroy(struct tal *);

typedef int (*foreach_uri_cb)(struct tal *, struct rpki_uri *, void *);
int foreach_uri(struct tal *, foreach_uri_cb, void *);
void tal_shuffle_uris(struct tal *);

char const *tal_get_file_name(struct tal *);
void tal_get_spki(struct tal *, unsigned char const **, size_t *);

int perform_standalone_validation(struct db_table *);
void terminate_standalone_validation(void);

#endif /* TAL_OBJECT_H_ */
