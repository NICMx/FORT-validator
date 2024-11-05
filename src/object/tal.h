#ifndef SRC_OBJECT_TAL_H_
#define SRC_OBJECT_TAL_H_

#include "stddef.h"

/* This is RFC 8630. */

struct tal;

char const *tal_get_file_name(struct tal *);
void tal_get_spki(struct tal *, unsigned char const **, size_t *);

int perform_standalone_validation(void);

#endif /* SRC_OBJECT_TAL_H_ */
