#ifndef SRC_RPP_H_
#define SRC_RPP_H_

#include <openssl/x509.h>

#include "types/map.h"

/* Repository Publication Point */
struct rpp {
	struct cache_mapping *files;
	size_t nfiles;				/* Number of maps in @files */

	struct {
		struct cache_mapping *map;	/* Points to @files entry */
		X509_CRL *obj;
	} crl;
};

void rpp_cleanup(struct rpp *);

#endif /* SRC_RPP_H_ */
