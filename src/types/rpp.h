#ifndef SRC_RPP_H_
#define SRC_RPP_H_

#include <openssl/x509.h>
#include <time.h>

#include "asn1/asn1c/INTEGER.h"
#include "types/map.h"

struct mft_meta {
	INTEGER_t num;				/* Manifest's manifestNumber */
	time_t update;				/* Manifest's thisUpdate */
};

/* Repository Publication Point */
struct rpp {
	struct cache_mapping *files;
	size_t nfiles;				/* Number of maps in @files */

	struct {
		struct cache_mapping *map;	/* Points to @files entry */
		X509_CRL *obj;
	} crl;

	struct mft_meta mft;
};

#define mftm_cleanup(m) INTEGER_cleanup(&(m)->num);
void rpp_cleanup(struct rpp *);

#endif /* SRC_RPP_H_ */
