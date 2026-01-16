#ifndef SRC_RPP_H_
#define SRC_RPP_H_

#include <openssl/x509.h>
#include <sys/stat.h>

#include "asn1/asn1c/INTEGER.h"
#include "cachefile.h"
#include "types/map.h"

struct mft_meta {
	INTEGER_t num;				/* Manifest's manifestNumber */
	time_t update;				/* Manifest's thisUpdate */
};

/* Repository Publication Point */
struct rpp {
	struct cache_file **files;
	size_t nfiles;				/* @files array length */

	struct {
		struct cache_file *file;	/* Points to @files entry */
		X509_CRL *obj;
	} crl;

	struct {
		struct cache_file *file;
		struct mft_meta meta;
	} mft;
};

#define mftm_cleanup(m) INTEGER_cleanup(&(m)->num);
void rpp_cleanup(struct rpp *);

#endif /* SRC_RPP_H_ */
