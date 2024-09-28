#include "rpp.h"

#include "types/array.h"

void
rpp_cleanup(struct rpp *rpp)
{
	array_index i;

	sk_X509_pop_free(rpp->ancestors, X509_free);

	for (i = 0; i < rpp->nfiles; i++)
		map_cleanup(&rpp->files[i]);
	free(rpp->files);

	if (rpp->crl.obj != NULL)
		X509_CRL_free(rpp->crl.obj);
}
