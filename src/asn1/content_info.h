#ifndef SRC_ASN1_CONTENT_INFO_H_
#define SRC_ASN1_CONTENT_INFO_H_

/* Some wrappers for asn1/asn1c/ContentInfo.h. */

#include "asn1/asn1c/ContentInfo.h"

int content_info_load(char const *, struct ContentInfo **);
void content_info_free(struct ContentInfo *);

#endif /* SRC_ASN1_CONTENT_INFO_H_ */
