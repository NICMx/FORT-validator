#ifndef TAL_OBJECT_H_
#define TAL_OBJECT_H_

/* This is RFC 8630. */

#include "cache/local_cache.h"
#include "rtr/db/db_table.h"

struct tal;

char const *tal_get_file_name(struct tal *);
void tal_get_spki(struct tal *, unsigned char const **, size_t *);
struct rpki_cache *tal_get_cache(struct tal *);

struct db_table *perform_standalone_validation(void);

#endif /* TAL_OBJECT_H_ */
