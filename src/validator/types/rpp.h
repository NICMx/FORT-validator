#ifndef VALIDATOR_TYPES_RPP_H_
#define VALIDATOR_TYPES_RPP_H_

#include <openssl/x509.h>

#include "validator/cachefile.h"

/* Repository Publication Point */
struct rpp {
	struct cache_file **files;
	/* @files array length */
	size_t nfiles;

	struct {
		/* Points to @files file, no refcount */
		struct cache_file *file;
		X509_CRL *obj;
	} crl;

	/* file points to @files file, no refcount */
	struct mft_meta mft;
};

#define mftm_cleanup(m) INTEGER_cleanup(&(m)->num);
void rpp_cleanup(struct rpp *);

#endif /* VALIDATOR_TYPES_RPP_H_ */
