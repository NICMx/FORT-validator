#include "types/rpp.h"

void
rpp_cleanup(struct rpp *rpp)
{
	free(rpp->files);
	rpp->files = NULL;
	rpp->nfiles = 0;

	rpp->crl.file = NULL;
	if (rpp->crl.obj != NULL) {
		X509_CRL_free(rpp->crl.obj);
		rpp->crl.obj = NULL;
	}

	rpp->mft.file = NULL;
	mftm_cleanup(&rpp->mft);
	memset(&rpp->mft, 0, sizeof(rpp->mft));
}
