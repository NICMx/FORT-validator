#ifndef SRC_RPP_H_
#define SRC_RPP_H_

#include <openssl/x509.h>
#include <sys/stat.h>

#include "asn1/asn1c/INTEGER.h"
#include "cachefile.h"
#include "types/map.h"

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

#endif /* SRC_RPP_H_ */
