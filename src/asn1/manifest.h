#ifndef SRC_ASN1_MANIFEST_H_
#define SRC_ASN1_MANIFEST_H_

#include <libcmscodec/Manifest.h>
#include <libcmscodec/SignedData.h>

int manifest_decode(struct SignedData *sdata, struct Manifest **mf);
void manifest_free(struct Manifest *mf);

#endif /* SRC_ASN1_MANIFEST_H_ */
