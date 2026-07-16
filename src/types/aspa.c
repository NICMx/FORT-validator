#include "types/aspa.h"

#include <stdio.h>
#include <stdlib.h>

#include "data_structure/common.h"

void
aspa_refget(struct aspa *aspa)
{
	aspa->refs++;
}

void
aspa_refput(struct aspa *aspa)
{
	if ((aspa->refs--) <= 1) {
		free(aspa->providers.asids);
		free(aspa);
	}
}

int
aspa_print(struct aspa const *aspa, void *arg)
{
	array_index i;
	printf("- [ASPA customerASID:%u\n", aspa->customer);
	for (i = 0; i < aspa->providers.count; i++)
		printf("    [Provider:%u]\n", aspa->providers.asids[i]);
	printf("  ]\n");
	return 0;
}

bool
providers_equal(struct aspa_providers *a, struct aspa_providers *b)
{
	array_index i;

	if (a == b)
		return true;
	if (!a || !b || (a->count != b->count))
		return false;

	for (i = 0; i < a->count; i++)
		if (a->asids[i] != b->asids[i])
			return false;

	return true;
}
