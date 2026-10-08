#ifndef VALIDATOR_ASN1_CONTENT_INFO_H_
#define VALIDATOR_ASN1_CONTENT_INFO_H_

/* Some wrappers for asn1/asn1c/ContentInfo.h. */

#include "validator/asn1/asn1c/ContentInfo.h"

int content_info_load(char const *, struct ContentInfo **);
void content_info_free(struct ContentInfo *);

#endif /* VALIDATOR_ASN1_CONTENT_INFO_H_ */
