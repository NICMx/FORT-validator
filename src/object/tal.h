#ifndef SRC_OBJECT_TAL_H_
#define SRC_OBJECT_TAL_H_

/* This is RFC 8630. */

#include "rtr/db/db_table.h"

struct tal;

char const *tal_get_file_name(struct tal *);
void tal_get_spki(struct tal *, unsigned char const **, size_t *);

struct db_table *perform_standalone_validation(void);

#endif /* SRC_OBJECT_TAL_H_ */
