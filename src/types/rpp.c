#include "types/rpp.h"

#include "types/array.h"

void
rpp_cleanup(struct rpp *rpp)
{
	array_index i;

	for (i = 0; i < rpp->nfiles; i++)
		map_cleanup(&rpp->files[i]);
	free(rpp->files);
	rpp->files = NULL;
	rpp->nfiles = 0;

	rpp->crl.map = NULL;
	if (rpp->crl.obj != NULL) {
		X509_CRL_free(rpp->crl.obj);
		rpp->crl.obj = NULL;
	}

	mftm_cleanup(&rpp->mft);
}
