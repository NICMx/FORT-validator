#ifndef SRC_TYPES_ASPA_H_
#define SRC_TYPES_ASPA_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct aspa_providers {
	/* Can be NULL and zero. If this happens, just withdraw. */
	uint32_t *asids;
	size_t count;
};

struct aspa {
	uint32_t customer;
	struct aspa_providers providers;

	int refs;
};

typedef int (*aspa_foreach_cb)(struct aspa const *, void *);

void aspa_refget(struct aspa *);
void aspa_refput(struct aspa *);
int aspa_print(struct aspa const *, void *);

bool providers_equal(struct aspa_providers *, struct aspa_providers *);

#endif /* SRC_TYPES_ASPA_H_ */
