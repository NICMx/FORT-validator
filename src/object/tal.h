#ifndef SRC_OBJECT_TAL_H_
#define SRC_OBJECT_TAL_H_

#include <stdatomic.h>
#include <stddef.h>
#include "types/uri.h"

/* This is RFC 8630. */

struct tal {
	char *path;
	struct uris urls;
	unsigned char *spki; /* Decoded; not base64. */
	size_t spki_len;

	atomic_uint refcount;
};

int perform_standalone_validation(void);

void tal_cleanup(struct tal *);

#endif /* SRC_OBJECT_TAL_H_ */
