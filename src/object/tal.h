#ifndef TAL_OBJECT_H_
#define TAL_OBJECT_H_

/* This is RFC 8630. */

#include <stddef.h>
#include "types/uri.h"
#include "rtr/db/db_table.h"
#include "thread/thread_pool.h"

struct tal;

int tal_load(char const *, struct tal **);
void tal_destroy(struct tal *);

char const *tal_get_file_name(struct tal *);
void tal_get_spki(struct tal *, unsigned char const **, size_t *);

int perform_standalone_validation(struct thread_pool *, struct db_table *);

#endif /* TAL_OBJECT_H_ */
