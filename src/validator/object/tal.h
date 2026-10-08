#ifndef VALIDATOR_OBJECT_TAL_H_
#define VALIDATOR_OBJECT_TAL_H_

#include <stdatomic.h>

#include "common/types/uri.h"
#include "validator/db/db_table.h"

/* This is RFC 8630. */

struct tal {
	char *path;
	struct uris urls;
	unsigned char *spki; /* Decoded; not base64. */
	size_t spki_len;

	atomic_uint refcount;
};

struct db_table *perform_standalone_validation(void);

void tal_cleanup(struct tal *);

#endif /* VALIDATOR_OBJECT_TAL_H_ */
