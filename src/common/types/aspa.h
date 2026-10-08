#ifndef SRC_TYPES_ASPA_H_
#define SRC_TYPES_ASPA_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct aspa_providers {
	/*
	 * If these are NULL and SIZE_MAX, it's because the customer ended up
	 * with too many providers after some provider merge. We need to retain
	 * the node and status to keep remembering that no more providers should
	 * be appended to the customer.
	 * When the customer has too many providers, it should be withdrawn from
	 * RTR.
	 */
	uint32_t *asids;
	size_t count;

#define AP_TOO_MANY_PROVIDERS(p) ((p)->asids == NULL && (p)->count == SIZE_MAX)
#define AP_IS_AS0(p) ((p)->count == 1 && (p)->asids[0] == 0)
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
