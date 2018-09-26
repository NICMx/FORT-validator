#ifndef SRC_ROA_H_
#define SRC_ROA_H_

#include <libcmscodec/RouteOriginAttestation.h>
#include <libcmscodec/SignedData.h>

int roa_decode(struct SignedData *, struct RouteOriginAttestation **);
void roa_free(struct RouteOriginAttestation *);

#endif /* SRC_ROA_H_ */
